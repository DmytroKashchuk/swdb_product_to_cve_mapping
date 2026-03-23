#!/usr/bin/env python3
"""
Diagnose CVE matching: for each vendor-product pair, shows what each tier returns
and WHY keyword fallback produces false positives.

Usage:
    python diagnose_cve_matches.py
    python diagnose_cve_matches.py --api-key YOUR_KEY
"""

import requests, time, argparse, json

NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0"

PAIRS = [
    ("AT Internet", "AT Internet", "at_internet", "at_internet"),
    ("AT&T", "VPN", "at%26t", "vpn"),
    ("COLT Technology Services", "VPN", "colt_technology_services", "vpn"),
    ("Deutsche Telekom", "VPN", "deutsche_telekom", "vpn"),
    ("Check Point", "VPN", "checkpoint", "vpn"),
    ("Check Point", "Check Point", "checkpoint", "check_point"),
    ("Telus", "VPN", "telus", "vpn"),
    ("Versatel", "VPN", "versatel", "vpn"),
    ("Invitel Solutions Inc", "VPN", "invitel_solutions_inc", "vpn"),
    ("Infor", "Infor", "infor", "infor"),
    ("Informa Group PLC", "Informa", "informa_group_plc", "informa"),
]

TARGET_CVE = "CVE-2024-24919"

def query_nvd(params, api_key="983cba50-1471-466c-a5cc-567621fcab31"):
    headers = {"apiKey": api_key} if api_key else {}
    r = requests.get(NVD, params={**params, "resultsPerPage": 5}, headers=headers, timeout=60)
    if r.status_code == 200:
        return r.json()
    print(f"    ERR {r.status_code}")
    return None

def check_cve_in_results(data, target=TARGET_CVE):
    if not data: return False, 0
    total = data.get("totalResults", 0)
    for v in data.get("vulnerabilities", []):
        if v.get("cve", {}).get("id") == target:
            return True, total
    return False, total

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--api-key", default="")
    args = p.parse_args()
    delay = 0.7 if args.api_key else 6.5

    print(f"{'='*90}")
    print(f"DIAGNOSING: Why does {TARGET_CVE} appear for unrelated vendors?")
    print(f"{'='*90}\n")

    results = []

    for vendor, product, cpe_v, cpe_p in PAIRS:
        print(f"\n{'─'*70}")
        print(f"VENDOR: {vendor}  |  PRODUCT: {product}")
        print(f"{'─'*70}")

        # TIER 1: CPE virtualMatchString
        cpe = f"cpe:2.3:a:{cpe_v}:{cpe_p}:*:*:*:*:*:*:*"
        print(f"\n  [Tier 1] virtualMatchString: {cpe}")
        data = query_nvd({"virtualMatchString": cpe}, args.api_key)
        found, total = check_cve_in_results(data)
        print(f"    Total CVEs: {total} | {TARGET_CVE} found: {found}")
        time.sleep(delay)

        # TIER 2: keyword vendor+product
        kw2 = f"{vendor} {product}" if vendor.lower() not in product.lower() else product
        print(f"\n  [Tier 2] keywordSearch: \"{kw2}\"")
        data = query_nvd({"keywordSearch": kw2}, args.api_key)
        found2, total2 = check_cve_in_results(data)
        print(f"    Total CVEs: {total2} | {TARGET_CVE} found: {found2}")
        if found2:
            print(f"    ⚠️  FALSE POSITIVE — keyword \"{kw2}\" matched CVE description text!")
        time.sleep(delay)

        # TIER 3: keyword product only
        if vendor.lower() not in product.lower():
            print(f"\n  [Tier 3] keywordSearch: \"{product}\"")
            data = query_nvd({"keywordSearch": product}, args.api_key)
            found3, total3 = check_cve_in_results(data)
            print(f"    Total CVEs: {total3} | {TARGET_CVE} found: {found3}")
            if found3:
                print(f"    ⚠️  FALSE POSITIVE — keyword \"{product}\" matched CVE description text!")
            time.sleep(delay)
        else:
            found3, total3 = False, 0

        # Also: what does CPE actually return for checkpoint products?
        row = {
            "vendor": vendor, "product": product,
            "tier1_cpe_total": total, "tier1_found": found,
            "tier2_kw": kw2, "tier2_total": total2, "tier2_found": found2,
            "tier3_kw": product, "tier3_total": total3, "tier3_found": found3,
        }
        results.append(row)

    # Now check the CORRECT CPE for Check Point
    print(f"\n\n{'='*90}")
    print("CONTROL: What the CORRECT CPE lookup returns")
    print(f"{'='*90}")

    correct_cpes = [
        ("checkpoint", "quantum_security_gateway_firmware"),
        ("checkpoint", "quantum_spark_firmware"),
        ("checkpoint", "cloudguard_network_security"),
    ]
    for cv, cp in correct_cpes:
        cpe = f"cpe:2.3:*:{cv}:{cp}:*:*:*:*:*:*:*"
        print(f"\n  virtualMatchString: {cpe}")
        data = query_nvd({"virtualMatchString": cpe}, args.api_key)
        found, total = check_cve_in_results(data)
        print(f"    Total CVEs: {total} | {TARGET_CVE} found: {found}")
        if found:
            print(f"    ✅ CORRECT MATCH via CPE")
        time.sleep(delay)

    # Summary
    print(f"\n\n{'='*90}")
    print("SUMMARY")
    print(f"{'='*90}")
    print(f"\n{'Vendor':<25} {'Product':<15} {'Tier1(CPE)':<12} {'Tier2(kw)':<12} {'Tier3(kw)':<12} {'Verdict'}")
    print("─" * 90)
    for r in results:
        t1 = "✅" if r["tier1_found"] else "—"
        t2 = "⚠️" if r["tier2_found"] else "—"
        t3 = "⚠️" if r["tier3_found"] else "—"
        verdict = "LEGIT (CPE)" if r["tier1_found"] else ("FALSE POS" if r["tier2_found"] or r["tier3_found"] else "NO MATCH")
        print(f"{r['vendor']:<25} {r['product']:<15} {t1:<12} {t2:<12} {t3:<12} {verdict}")

    print(f"\nKeyword search matches on CVE DESCRIPTION text, not on affected products.")
    print(f"'VPN' matches because description says 'remote Access VPN'")
    print(f"'Infor' matches because description contains 'information'")
    print(f"'AT Internet' matches because description contains 'internet'")
    print(f"\nFIX: Only use Tier 1 (CPE virtualMatchString). Drop keyword fallback,")
    print(f"or validate keyword results by checking their CPE configurations match your vendor.")

if __name__ == "__main__":
    main()