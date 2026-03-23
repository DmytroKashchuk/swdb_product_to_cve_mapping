#!/usr/bin/env python3
"""
Fix CPE mapping: heuristic cleaning + NVD CPE dictionary validation.

Phase 1: Rule-based cleaning (instant, no API)
Phase 2: NVD CPE keyword search to find real CPE names (optional, needs API)

Usage:
    python fix_cpe_mapping.py                          # Phase 1 only
    python fix_cpe_mapping.py --validate               # Phase 1 + 2
    python fix_cpe_mapping.py --validate --api-key KEY  # Faster with API key
"""

import csv, re, argparse, time, json, os

try:
    import requests
except ImportError:
    requests = None

INPUT = "tech_with_cpe_mapping.csv"
OUTPUT = "tech_with_cpe_mapping_fixed.csv"
CACHE_FILE = "cpe_lookup_cache.json"
NVD_CPE_API = "https://services.nvd.nist.gov/rest/json/cpes/2.0"

# ── Legal suffixes to strip from vendor names ──
LEGAL_SUFFIXES = [
    r'\s*,?\s*\bInc\.?\s*$', r'\s*,?\s*\bLLC\.?\s*$', r'\s*,?\s*\bLtd\.?\s*$',
    r'\s*,?\s*\bGmbH\s*$', r'\s*,?\s*\bCorp\.?\s*$',
    r'\s*,?\s*\bPLC\s*$', r'\s*,?\s*\bAG\s*$',
    r'\s*,?\s*\bCorporation\s*$', r'\s*,?\s*\bIncorporated\s*$',
    r'\s*,?\s*\bLimited\s*$', r'\s*,?\s*\bCompany\s*$',
    r'^The\s+', r'\s+ADR$',
    r'\s*\([^)]*\)\s*$',  # trailing parenthetical like "(US)"
]

# ── Known vendor name mappings (HTTP Archive → NVD CPE) ──
VENDOR_OVERRIDES = {
    "the apache software foundation": "apache",
    "apache software foundation": "apache",
    "check point": "checkpoint",
    "check point software technologies": "checkpoint",
    "cisco systems": "cisco",
    "cisco systems inc": "cisco",
    "hewlett packard enterprise": "hp",
    "hewlett-packard": "hp",
    "palo alto networks": "paloaltonetworks",
    "juniper networks": "juniper",
    "fortinet": "fortinet",
    "f5 networks": "f5",
    "vmware": "vmware",
    "ibm corporation": "ibm",
    "oracle corporation": "oracle",
    "sap se": "sap",
    "red hat": "redhat",
    "mozilla foundation": "mozilla",
    "elastic": "elastic",
    "atlassian": "atlassian",
    "jetbrains": "jetbrains",
    "automattic": "automattic",
    "wordpress.org": "wordpress",
    "adobe systems": "adobe",
    "adobe": "adobe",
    "microsoft": "microsoft",
    "google": "google",
    "amazon": "amazon",
    "amazon web services": "amazon",
    "apple": "apple",
    "samsung": "samsung",
    "dell": "dell",
    "dell technologies": "dell",
    "intel": "intel",
    "nvidia": "nvidia",
    "salesforce": "salesforce",
    "salesforce.com": "salesforce",
    "sophos": "sophos",
    "symantec": "symantec",
    "trend micro": "trendmicro",
    "mcafee": "mcafee",
    "citrix": "citrix",
    "citrix systems": "citrix",
    "barracuda networks": "barracuda",
    "sonicwall": "sonicwall",
    "dell sonicwall": "sonicwall",
    "progress software": "progress",
    "progress software corporation": "progress",
    "the nielsen company": "nielsen",
    "a medium corporation": "medium",
}

# ── Known product name mappings ──
PRODUCT_OVERRIDES = {
    ("microsoft", "microsoft sharepoint 2013"): "sharepoint_server",
    ("microsoft", "microsoft sharepoint 2010"): "sharepoint_server",
    ("microsoft", "microsoft exchange 2013"): "exchange_server",
    ("microsoft", "microsoft exchange 2010"): "exchange_server",
    ("microsoft", "microsoft exchange 2007"): "exchange_server",
    ("microsoft", "microsoft exchange 2003"): "exchange_server",
    ("microsoft", "microsoft exchange 2000"): "exchange_server",
    ("microsoft", "microsoft exchange 5.0"): "exchange_server",
    ("microsoft", "microsoft lync"): "lync",
    ("microsoft", "microsoft teams"): "teams",
    ("microsoft", "microsoft office"): "office",
    ("microsoft", "microsoft live meeting"): "live_meeting",
    ("microsoft", "microsoft bpos"): "business_productivity_online_suite",
    ("cisco", "cisco jabber"): "jabber",
    ("cisco", "cisco spark"): "spark",
    ("cisco", "cisco webex event center"): "webex_event_center",
    ("cisco", "cisco webex weboffice"): "webex",
    ("cisco", "cisco codian"): "codian",
    ("cisco", "cisco unified meetingplace"): "unified_meetingplace",
    ("cisco", "cisco mx300"): "telepresence_mx_series",
    ("cisco", "cisco mx200"): "telepresence_mx_series",
    ("cisco", "cisco prime collaboration manager"): "prime_collaboration",
    ("adobe", "adobe photoshop"): "photoshop",
    ("adobe", "adobe illustrator"): "illustrator",
    ("adobe", "adobe indesign"): "indesign",
    ("adobe", "adobe after effects"): "after_effects",
    ("adobe", "adobe captivate"): "captivate",
    ("adobe", "adobe creative suite"): "creative_suite",
    ("adobe", "adobe pagemaker"): "pagemaker",
    ("adobe", "adobe experience manager assets"): "experience_manager",
    ("adobe", "adobe media optimizer"): "media_optimizer",
    ("adobe", "adobe audience manager"): "audience_manager",
    ("adobe", "adobe dtm"): "dynamic_tag_management",
    ("google", "google ads"): "ads",
    ("google", "google adsense"): "adsense",
    ("google", "google doubleclick"): "doubleclick",
    ("google", "google remarketing"): "remarketing",
    ("apache", "apache solr"): "solr",
    ("apache", "apache lucene"): "lucene",
    ("apache", "apache tomcat"): "tomcat",
    ("apache", "apache http server"): "http_server",
    ("apache", "apache struts"): "struts",
}


def clean_vendor(raw_vendor):
    v = raw_vendor.strip()
    # Strip legal suffixes first
    for pat in LEGAL_SUFFIXES:
        v = re.sub(pat, '', v, flags=re.IGNORECASE).strip()
    v = re.sub(r'[\.\,]+$', '', v).strip()
    # Check override table (try multiple variations)
    key = v.lower()
    if key in VENDOR_OVERRIDES:
        return VENDOR_OVERRIDES[key]
    # Try without trailing dots/periods
    key2 = re.sub(r'\.$', '', key)
    if key2 in VENDOR_OVERRIDES:
        return VENDOR_OVERRIDES[key2]
    return re.sub(r'[\s\-\.]+', '_', v).lower().strip('_')


def clean_product(raw_product, cpe_vendor):
    p = raw_product.strip()
    key = (cpe_vendor, p.lower())
    if key in PRODUCT_OVERRIDES:
        return PRODUCT_OVERRIDES[key]

    # Strip vendor name prefix from product (only if something remains)
    vendor_words = cpe_vendor.replace('_', ' ')
    p_lower = p.lower()
    if p_lower.startswith(vendor_words + ' ') and len(p) > len(vendor_words) + 1:
        p = p[len(vendor_words) + 1:]
    # Also handle "CiscoJabber" → "Jabber" style (no space)
    elif p_lower.startswith(vendor_words) and len(p) > len(vendor_words):
        remainder = p[len(vendor_words):]
        if remainder[0].isupper() or remainder[0] == ' ':
            p = remainder.lstrip()

    # Strip version numbers at end (e.g. "Exchange 2013" → "Exchange")
    p = re.sub(r'\s+\d[\d\.]*$', '', p)
    # Strip edition markers
    p = re.sub(r'\s+(Enterprise|Professional|Standard|Community|Express|Free|Lite)\s*$', '', p, flags=re.IGNORECASE)

    result = re.sub(r'[\s\-\.]+', '_', p).lower().strip('_')
    return result if result else raw_product.lower().replace(' ', '_')


def load_cache():
    if os.path.exists(CACHE_FILE):
        with open(CACHE_FILE) as f:
            return json.load(f)
    return {}


def save_cache(cache):
    with open(CACHE_FILE, 'w') as f:
        json.dump(cache, f, indent=2)


def search_cpe_dictionary(vendor, product, api_key="", delay=6.5):
    """Search NVD CPE dictionary for a matching CPE name."""
    headers = {"apiKey": api_key} if api_key else {}
    kw = f"{vendor} {product}".replace('_', ' ')
    params = {"keywordSearch": kw, "resultsPerPage": 10}
    try:
        r = requests.get(NVD_CPE_API, params=params, headers=headers, timeout=30)
        if r.status_code == 200:
            data = r.json()
            products = data.get("products", [])
            matches = []
            for p in products:
                cpe_name = p.get("cpe", {}).get("cpeName", "")
                # Parse cpe:2.3:a:vendor:product:...
                parts = cpe_name.split(':')
                if len(parts) >= 5:
                    matches.append({
                        "cpeName": cpe_name,
                        "cpe_vendor": parts[3],
                        "cpe_product": parts[4],
                    })
            return matches
        elif r.status_code == 403:
            print(f"    Rate limited, waiting 30s...")
            time.sleep(30)
            return search_cpe_dictionary(vendor, product, api_key, delay)
    except Exception as e:
        print(f"    Error: {e}")
    return []


def pick_best_match(matches, target_vendor, target_product):
    """Pick the best CPE match using simple token overlap scoring."""
    tv = set(target_vendor.split('_'))
    tp = set(target_product.split('_'))
    best, best_score = None, -1

    for m in matches:
        mv = set(m["cpe_vendor"].split('_'))
        mp = set(m["cpe_product"].split('_'))
        # Vendor overlap + product overlap
        v_score = len(tv & mv) / max(len(tv | mv), 1)
        p_score = len(tp & mp) / max(len(tp | mp), 1)
        score = v_score + p_score * 2  # Weight product match higher
        if score > best_score:
            best_score = score
            best = m
    return best, best_score


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--input", default=INPUT)
    p.add_argument("--validate", action="store_true", help="Phase 2: validate against NVD CPE dictionary")
    p.add_argument("--api-key", default="")
    p.add_argument("--limit", type=int, default=0, help="Limit validation to N rows")
    args = p.parse_args()

    with open(args.input) as f:
        reader = csv.DictReader(f)
        rows = list(reader)
    print(f"Loaded {len(rows)} technologies\n")

    # ── Phase 1: Heuristic cleaning ──
    print("=" * 60)
    print("PHASE 1: Heuristic cleaning")
    print("=" * 60)

    changed_vendor = 0
    changed_product = 0

    for row in rows:
        old_v = row["cpe_vendor"]
        old_p = row["cpe_product"]

        new_v = clean_vendor(row["VendorName"])
        new_p = clean_product(row["Product"], new_v)

        if new_v != old_v:
            changed_vendor += 1
        if new_p != old_p:
            changed_product += 1

        row["cpe_vendor_old"] = old_v
        row["cpe_product_old"] = old_p
        row["cpe_vendor"] = new_v
        row["cpe_product"] = new_p
        row["cpe_match_string"] = f"cpe:2.3:a:{new_v}:{new_p}:*:*:*:*:*:*:*"
        row["nvd_api_url"] = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName=cpe:2.3:a:{new_v}:{new_p}:*:*:*:*:*:*:*"

    print(f"  Vendors cleaned: {changed_vendor}")
    print(f"  Products cleaned: {changed_product}")

    # Show some examples
    print(f"\n  Sample changes:")
    shown = 0
    for row in rows:
        if row["cpe_vendor_old"] != row["cpe_vendor"] or row["cpe_product_old"] != row["cpe_product"]:
            print(f"    {row['cpe_vendor_old']}:{row['cpe_product_old']}")
            print(f"    → {row['cpe_vendor']}:{row['cpe_product']}")
            print()
            shown += 1
            if shown >= 10:
                break

    # ── Phase 2: NVD CPE dictionary validation ──
    if args.validate and requests:
        print("=" * 60)
        print("PHASE 2: NVD CPE dictionary validation")
        print("=" * 60)

        delay = 0.7 if args.api_key else 6.5
        cache = load_cache()
        validated = 0
        corrected = 0
        not_found = 0
        limit = args.limit if args.limit > 0 else len(rows)

        for i, row in enumerate(rows[:limit]):
            key = f"{row['cpe_vendor']}:{row['cpe_product']}"
            if key in cache:
                result = cache[key]
            else:
                print(f"  [{i+1}/{limit}] Searching: {key}")
                matches = search_cpe_dictionary(row['cpe_vendor'], row['cpe_product'], args.api_key, delay)
                if matches:
                    best, score = pick_best_match(matches, row['cpe_vendor'], row['cpe_product'])
                    result = {"found": True, "best": best, "score": score, "n_matches": len(matches)}
                else:
                    result = {"found": False}
                cache[key] = result
                time.sleep(delay)

                if (i + 1) % 50 == 0:
                    save_cache(cache)

            if result["found"] and result["best"]:
                validated += 1
                bv = result["best"]["cpe_vendor"]
                bp = result["best"]["cpe_product"]
                if bv != row["cpe_vendor"] or bp != row["cpe_product"]:
                    corrected += 1
                    if corrected <= 20:
                        print(f"    CORRECTED: {row['cpe_vendor']}:{row['cpe_product']} → {bv}:{bp} (score={result['score']:.2f})")
                    row["cpe_vendor"] = bv
                    row["cpe_product"] = bp
                    row["cpe_match_string"] = f"cpe:2.3:a:{bv}:{bp}:*:*:*:*:*:*:*"
            else:
                not_found += 1

        save_cache(cache)
        print(f"\n  Validated: {validated}")
        print(f"  Corrected: {corrected}")
        print(f"  Not found in CPE dictionary: {not_found}")

    # ── Write output ──
    fieldnames = list(rows[0].keys())
    # Remove temp fields
    for temp in ["cpe_vendor_old", "cpe_product_old"]:
        if temp in fieldnames:
            fieldnames.remove(temp)

    with open(OUTPUT, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
        writer.writeheader()
        writer.writerows(rows)

    print(f"\nOutput: {OUTPUT}")
    print("Done!")


if __name__ == "__main__":
    main()