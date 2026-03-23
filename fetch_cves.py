#!/usr/bin/env python3
"""
CVE Fetcher for Technology Install Base (v2 — Fixed + Paginated)
=================================================================
Uses a 3-tier lookup strategy against the NVD API v2.0:

  1. virtualMatchString — matches CPE patterns against CVE applicability
     statements (supports wildcards, unlike cpeName which requires exact match)
  2. Keyword search (vendor + product) — searches CVE descriptions
  3. Keyword search (product only) — broader fallback

**Key fix in this version**: Full pagination support. The NVD API returns a
max of 2,000 results per request. This script now loops through all pages
using startIndex so no CVEs are missed for high-volume products.

Usage:
    python fetch_cves_v2.py                        # Process all technologies
    python fetch_cves_v2.py --limit 50             # Process first 50 only
    python fetch_cves_v2.py --category "Anti-Virus" # Filter by product category
    python fetch_cves_v2.py --resume                # Resume from last checkpoint

Requirements:
    pip install requests

Notes:
    - NVD API rate limit: 5 requests/30s without API key, 50 requests/30s with key.
    - Get a free API key at https://nvd.nist.gov/developers/request-an-api-key
    - Pass it via: python fetch_cves_v2.py --api-key YOUR_KEY
"""

import csv
import json
import time
import argparse
import os
import sys
from datetime import datetime

try:
    import requests
except ImportError:
    print("ERROR: 'requests' library required. Install with: pip install requests")
    sys.exit(1)

NVD_CVE_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
PAGE_SIZE = 2000  # NVD max per page
CHECKPOINT_FILE = "fetch_progress.json"
RESULTS_FILE = "tech_cve_results.csv"
SUMMARY_FILE = "tech_cve_summary.csv"


def parse_args():
    p = argparse.ArgumentParser(description="Fetch CVEs for technologies via NVD API v2 (paginated)")
    p.add_argument("--input", default="tech_with_cpe_mapping.csv", help="Input CSV with CPE mappings")
    p.add_argument("--limit", type=int, default=0, help="Process only first N technologies (0=all)")
    p.add_argument("--category", type=str, default="", help="Filter to a specific ProductCategory")
    p.add_argument("--api-key", type=str, default="", help="NVD API key (speeds up queries 10x)")
    p.add_argument("--resume", action="store_true", help="Resume from last checkpoint")
    p.add_argument("--delay", type=float, default=6.5,
                   help="Seconds between requests (default 6.5 for no API key)")
    p.add_argument("--max-cves", type=int, default=0,
                   help="Cap CVEs fetched per product (0=unlimited). Useful for huge products.")
    return p.parse_args()


def load_checkpoint():
    if os.path.exists(CHECKPOINT_FILE):
        with open(CHECKPOINT_FILE, 'r') as f:
            return json.load(f)
    return {"completed": [], "last_index": 0}


def save_checkpoint(checkpoint):
    with open(CHECKPOINT_FILE, 'w') as f:
        json.dump(checkpoint, f)


def _do_request(params, api_key="", max_retries=3):
    """Send a GET to NVD CVE API with given params. Returns parsed JSON or None."""
    headers = {}
    if api_key:
        headers["apiKey"] = api_key

    for attempt in range(1, max_retries + 1):
        try:
            resp = requests.get(NVD_CVE_API, params=params, headers=headers, timeout=60)
            if resp.status_code == 200:
                return resp.json()
            elif resp.status_code == 403:
                wait = 30 * attempt
                print(f"    [WARN] 403 rate-limited. Sleeping {wait}s (attempt {attempt}/{max_retries})...")
                time.sleep(wait)
            elif resp.status_code == 503:
                wait = 15 * attempt
                print(f"    [WARN] 503 Service unavailable. Sleeping {wait}s (attempt {attempt}/{max_retries})...")
                time.sleep(wait)
            else:
                print(f"    [WARN] NVD returned status {resp.status_code}")
                return None
        except requests.exceptions.Timeout:
            wait = 10 * attempt
            print(f"    [WARN] Request timed out. Sleeping {wait}s (attempt {attempt}/{max_retries})...")
            time.sleep(wait)
        except Exception as e:
            print(f"    [ERROR] Request failed: {e}")
            return None

    print(f"    [ERROR] All {max_retries} attempts failed.")
    return None


def _paginated_fetch(params, api_key="", delay=6.5, max_cves=0):
    """
    Fetch ALL results for the given NVD query params, paginating as needed.

    Returns a list of all vulnerability records across all pages.
    """
    all_vulns = []
    start_index = 0
    total_results = None  # unknown until first response

    while True:
        page_params = {**params, "startIndex": start_index, "resultsPerPage": PAGE_SIZE}
        data = _do_request(page_params, api_key)

        if not data:
            break

        total_results = data.get("totalResults", 0)
        page_vulns = data.get("vulnerabilities", [])
        all_vulns.extend(page_vulns)

        fetched_so_far = len(all_vulns)

        # Log pagination progress for large result sets
        if total_results > PAGE_SIZE:
            print(f"    Fetched {fetched_so_far}/{total_results} CVEs...")

        # Check if we've hit the optional per-product cap
        if max_cves > 0 and fetched_so_far >= max_cves:
            print(f"    Reached --max-cves cap ({max_cves}), stopping pagination.")
            all_vulns = all_vulns[:max_cves]
            break

        # Check if there are more pages
        if fetched_so_far >= total_results:
            break  # all done

        start_index = fetched_so_far
        time.sleep(delay)  # respect rate limit between pages

    return all_vulns, total_results or 0


def query_by_virtual_match(cpe_vendor, cpe_product, api_key="", delay=6.5, max_cves=0):
    """
    Tier 1: Use virtualMatchString to find CVEs whose applicability statements
    match a CPE pattern like cpe:2.3:a:openx:openx:*:*:*:*:*:*:*
    """
    virtual_cpe = f"cpe:2.3:a:{cpe_vendor}:{cpe_product}:*:*:*:*:*:*:*"
    params = {"virtualMatchString": virtual_cpe}
    return _paginated_fetch(params, api_key, delay, max_cves)


def query_by_keyword(search_terms, api_key="", delay=6.5, max_cves=0):
    """
    Tier 2/3: Search CVE descriptions by keyword.
    """
    params = {"keywordSearch": search_terms}
    return _paginated_fetch(params, api_key, delay, max_cves)


def extract_cve_details(vuln_data):
    """Extract key fields from an NVD vulnerability record."""
    cve = vuln_data.get("cve", {})
    cve_id = cve.get("id", "")
    descriptions = cve.get("descriptions", [])
    desc = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")

    metrics = cve.get("metrics", {})
    severity = ""
    base_score = ""

    for version in ["cvssMetricV31", "cvssMetricV30"]:
        if version in metrics and metrics[version]:
            cvss = metrics[version][0].get("cvssData", {})
            base_score = cvss.get("baseScore", "")
            severity = cvss.get("baseSeverity", "")
            break

    if not severity and "cvssMetricV2" in metrics and metrics["cvssMetricV2"]:
        cvss2 = metrics["cvssMetricV2"][0].get("cvssData", {})
        base_score = cvss2.get("baseScore", "")
        severity = metrics["cvssMetricV2"][0].get("baseSeverity", "")

    published = cve.get("published", "")[:10]

    return {
        "cve_id": cve_id,
        "description": desc[:500],
        "base_score": base_score,
        "severity": severity,
        "published_date": published,
    }


def main():
    args = parse_args()
    delay = args.delay if not args.api_key else max(0.7, args.delay / 10)

    with open(args.input, 'r') as f:
        reader = csv.DictReader(f)
        techs = list(reader)

    if args.category:
        techs = [t for t in techs if t["ProductCategory"] == args.category]
        print(f"Filtered to category '{args.category}': {len(techs)} technologies")

    if args.limit > 0:
        techs = techs[:args.limit]

    print(f"Processing {len(techs)} technologies...")
    print(f"Delay between requests: {delay}s")
    if args.max_cves:
        print(f"Max CVEs per product: {args.max_cves}")
    else:
        print(f"Max CVEs per product: unlimited (full pagination)")
    if args.api_key:
        print("Using API key (faster rate limit)")
    else:
        print("No API key — using conservative rate limit. Get a free key at:")
        print("  https://nvd.nist.gov/developers/request-an-api-key")
    print()

    checkpoint = load_checkpoint() if args.resume else {"completed": [], "last_index": 0}
    completed_set = set(checkpoint["completed"])
    start_idx = checkpoint["last_index"] if args.resume else 0

    results_mode = 'a' if args.resume and os.path.exists(RESULTS_FILE) else 'w'
    summary_rows = []

    with open(RESULTS_FILE, results_mode, newline='') as rf:
        result_writer = csv.DictWriter(rf, fieldnames=[
            "VendorName", "Product", "ProductCategory", "cve_id",
            "base_score", "severity", "published_date", "description", "match_method"
        ])
        if results_mode == 'w':
            result_writer.writeheader()

        for i, tech in enumerate(techs[start_idx:], start=start_idx):
            key = f"{tech['VendorName']}|{tech['Product']}"
            if key in completed_set:
                continue

            vendor = tech["VendorName"]
            product = tech["Product"]
            cpe_vendor = tech["cpe_vendor"]
            cpe_product = tech["cpe_product"]

            print(f"[{i+1}/{len(techs)}] {vendor} — {product}")

            # ── Tier 1: virtualMatchString (CPE wildcard match) ──
            vulns, total_available = query_by_virtual_match(
                cpe_vendor, cpe_product, args.api_key, delay, args.max_cves
            )
            match_method = "virtualMatchString"
            if total_available > 0:
                print(f"    CPE match: {total_available} total CVEs in NVD")
            time.sleep(delay)

            # ── Tier 2: Keyword search (vendor + product) ──
            if not vulns:
                search_terms = f"{vendor} {product}"
                if vendor.lower() in product.lower():
                    search_terms = product
                print(f"    No CPE match, trying keyword: '{search_terms}'")
                vulns, total_available = query_by_keyword(
                    search_terms, args.api_key, delay, args.max_cves
                )
                match_method = "keyword_vendor_product"
                time.sleep(delay)

            # ── Tier 3: Keyword search (product only) ──
            if not vulns and vendor.lower() not in product.lower():
                print(f"    Trying product-only keyword: '{product}'")
                vulns, total_available = query_by_keyword(
                    product, args.api_key, delay, args.max_cves
                )
                match_method = "keyword_product_only"
                time.sleep(delay)

            cve_count = len(vulns)
            severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}

            for v in vulns:
                details = extract_cve_details(v)
                sev = details["severity"].upper()
                if sev in severity_counts:
                    severity_counts[sev] += 1

                result_writer.writerow({
                    "VendorName": vendor,
                    "Product": product,
                    "ProductCategory": tech["ProductCategory"],
                    "cve_id": details["cve_id"],
                    "base_score": details["base_score"],
                    "severity": details["severity"],
                    "published_date": details["published_date"],
                    "description": details["description"],
                    "match_method": match_method,
                })

            rf.flush()

            summary_rows.append({
                "VendorName": vendor,
                "Product": product,
                "ProductCategory": tech["ProductCategory"],
                "ProductSeries": tech["ProductSeries"],
                "cpe_vendor": cpe_vendor,
                "cpe_product": cpe_product,
                "total_cves": cve_count,
                "total_available_in_nvd": total_available,
                "critical": severity_counts["CRITICAL"],
                "high": severity_counts["HIGH"],
                "medium": severity_counts["MEDIUM"],
                "low": severity_counts["LOW"],
                "match_method": match_method,
            })

            sev_str = (f" ({severity_counts['CRITICAL']}C/{severity_counts['HIGH']}H/"
                       f"{severity_counts['MEDIUM']}M/{severity_counts['LOW']}L)") if cve_count else ""
            print(f"    Found {cve_count} CVEs via {match_method}{sev_str}")

            completed_set.add(key)
            if (i + 1) % 25 == 0:
                save_checkpoint({"completed": list(completed_set), "last_index": i + 1})
                print(f"    [Checkpoint saved at {i+1}]")

    # Write summary
    with open(SUMMARY_FILE, 'w', newline='') as sf:
        writer = csv.DictWriter(sf, fieldnames=[
            "VendorName", "Product", "ProductCategory", "ProductSeries",
            "cpe_vendor", "cpe_product",
            "total_cves", "total_available_in_nvd",
            "critical", "high", "medium", "low", "match_method"
        ])
        writer.writeheader()
        writer.writerows(summary_rows)

    total_cves = sum(r["total_cves"] for r in summary_rows)
    with_cves = sum(1 for r in summary_rows if r["total_cves"] > 0)
    print(f"\n{'='*60}")
    print(f"Done! Processed {len(summary_rows)} technologies")
    print(f"  {with_cves} technologies have known CVEs")
    print(f"  {total_cves} total CVE records fetched")
    print(f"\nOutput files:")
    print(f"  {RESULTS_FILE}  — detailed CVE list (one row per CVE)")
    print(f"  {SUMMARY_FILE}  — summary (one row per technology)")


if __name__ == "__main__":
    main()