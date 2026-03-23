"""
Download ALL CPEs from the NVD (NIST) API and export to CSV.

Usage:
    pip install requests
    python download_all_cpes.py --api-key YOUR_API_KEY

Output:
    all_cpes.csv  (in the same directory)

CPE 2.3 format:
    cpe:2.3:{part}:{vendor}:{product}:{version}:{update}:{edition}:{language}:{sw_edition}:{target_sw}:{target_hw}:{other}
"""

import argparse
import csv
import time
import sys
import requests

NVD_CPE_URL = "https://services.nvd.nist.gov/rest/2.0/cpes"
RESULTS_PER_PAGE = 2000  # max allowed by NVD API
OUTPUT_FILE = "all_cpes.csv"

CSV_HEADERS = [
    "cpe23Uri",
    "part",
    "vendor",
    "product",
    "version",
    "update",
    "edition",
    "language",
    "sw_edition",
    "target_sw",
    "target_hw",
    "other",
    "cpe_name_id",
    "title",
    "deprecated",
    "last_modified",
]


def parse_cpe23(cpe_string: str) -> dict:
    """Parse a CPE 2.3 URI string into its individual components."""
    # cpe:2.3:part:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other
    parts = cpe_string.split(":")
    fields = [
        "cpe_prefix",
        "cpe_version",
        "part",
        "vendor",
        "product",
        "version",
        "update",
        "edition",
        "language",
        "sw_edition",
        "target_sw",
        "target_hw",
        "other",
    ]
    parsed = {}
    for i, field in enumerate(fields):
        parsed[field] = parts[i] if i < len(parts) else "*"
    return parsed


def fetch_cpes(api_key: str, start_index: int = 0) -> dict:
    """Fetch a page of CPEs from the NVD API."""
    headers = {"apiKey": api_key}
    params = {
        "startIndex": start_index,
        "resultsPerPage": RESULTS_PER_PAGE,
    }
    response = requests.get(NVD_CPE_URL, headers=headers, params=params, timeout=120)
    response.raise_for_status()
    return response.json()


def main():
    parser = argparse.ArgumentParser(description="Download all CPEs from NVD API to CSV")
    parser.add_argument("--api-key", required=True, help="Your NVD API key")
    parser.add_argument("--output", default=OUTPUT_FILE, help=f"Output CSV file (default: {OUTPUT_FILE})")
    parser.add_argument("--delay", type=float, default=0.6,
                        help="Delay in seconds between API calls (default: 0.6 — with API key you get ~50 req/30s)")
    args = parser.parse_args()

    print(f"Fetching CPEs from NVD API...")
    print(f"Output file: {args.output}")
    print(f"Delay between requests: {args.delay}s")
    print("-" * 60)

    start_index = 0
    total_results = None
    total_written = 0

    with open(args.output, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=CSV_HEADERS)
        writer.writeheader()

        while True:
            try:
                data = fetch_cpes(args.api_key, start_index)
            except requests.exceptions.HTTPError as e:
                if e.response.status_code == 403:
                    print(f"\n[ERROR] 403 Forbidden — check your API key.")
                    sys.exit(1)
                elif e.response.status_code == 503:
                    print(f"\n[WARN] 503 Service Unavailable — retrying in 10s...")
                    time.sleep(10)
                    continue
                elif e.response.status_code == 429:
                    print(f"\n[WARN] 429 Rate limited — waiting 30s...")
                    time.sleep(30)
                    continue
                else:
                    raise
            except requests.exceptions.RequestException as e:
                print(f"\n[WARN] Connection error: {e} — retrying in 10s...")
                time.sleep(10)
                continue

            if total_results is None:
                total_results = data.get("totalResults", 0)
                print(f"Total CPEs to download: {total_results:,}")
                print("-" * 60)

            products = data.get("products", [])
            if not products:
                break

            for item in products:
                cpe = item.get("cpe", {})
                cpe_name = cpe.get("cpeName", "")
                parsed = parse_cpe23(cpe_name)

                # Get English title if available
                titles = cpe.get("titles", [])
                title = ""
                for t in titles:
                    if t.get("lang", "") == "en":
                        title = t.get("title", "")
                        break
                if not title and titles:
                    title = titles[0].get("title", "")

                row = {
                    "cpe23Uri": cpe_name,
                    "part": parsed.get("part", ""),
                    "vendor": parsed.get("vendor", ""),
                    "product": parsed.get("product", ""),
                    "version": parsed.get("version", ""),
                    "update": parsed.get("update", ""),
                    "edition": parsed.get("edition", ""),
                    "language": parsed.get("language", ""),
                    "sw_edition": parsed.get("sw_edition", ""),
                    "target_sw": parsed.get("target_sw", ""),
                    "target_hw": parsed.get("target_hw", ""),
                    "other": parsed.get("other", ""),
                    "cpe_name_id": cpe.get("cpeNameId", ""),
                    "title": title,
                    "deprecated": cpe.get("deprecated", False),
                    "last_modified": cpe.get("lastModified", ""),
                }
                writer.writerow(row)
                total_written += 1

            start_index += RESULTS_PER_PAGE
            progress = min(start_index, total_results)
            pct = (progress / total_results * 100) if total_results else 0
            print(f"  Downloaded {progress:,} / {total_results:,} ({pct:.1f}%)")

            if start_index >= total_results:
                break

            time.sleep(args.delay)

    print("-" * 60)
    print(f"Done! {total_written:,} CPEs written to {args.output}")


if __name__ == "__main__":
    main()
