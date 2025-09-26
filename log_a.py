#!/usr/bin/env python3
"""
log_analyzer.py
- Parses /var/log/auth.log for "Failed password"
- Allows configurable threshold
- Exports suspicious IPs to suspicious_ips.txt and suspicious_ips.csv
- Optionally prints a pandas table summary
"""

import re
from collections import Counter
import argparse
from pathlib import Path

try:
    import pandas as pd
except Exception:
    pd = None

LOG_PATH_DEFAULT = "/var/log/auth.log"
IP_PATTERN = r"Failed password.*from (\d+\.\d+\.\d+\.\d+)"

def analyze_log(file_path, threshold=5):
    failed_ips = []
    pattern = re.compile(IP_PATTERN)

    with open(file_path, "r", errors="ignore") as f:
        for line in f:
            m = pattern.search(line)
            if m:
                failed_ips.append(m.group(1))

    counter = Counter(failed_ips)
    suspicious = {ip: cnt for ip, cnt in counter.items() if cnt >= threshold}
    return counter, suspicious

def export_suspicious(suspicious, out_txt="suspicious_ips.txt", out_csv="suspicious_ips.csv"):
    # TXT
    with open(out_txt, "w") as f:
        for ip, cnt in suspicious.items():
            f.write(f"{ip} {cnt}\n")

    # CSV (pandas if available, else simple)
    if pd is not None:
        df = pd.DataFrame(list(suspicious.items()), columns=["ip","failed_attempts"])
        df.to_csv(out_csv, index=False)
    else:
        with open(out_csv, "w") as f:
            f.write("ip,failed_attempts\n")
            for ip, cnt in suspicious.items():
                f.write(f"{ip},{cnt}\n")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--log", default=LOG_PATH_DEFAULT, help="Path to log file")
    parser.add_argument("--threshold", type=int, default=3, help="Failed attempts threshold")
    parser.add_argument("--export", action="store_true", help="Export suspicious IPs to files")
    parser.add_argument("--show-table", action="store_true", help="Show pandas table (if pandas installed)")
    args = parser.parse_args()

    counter, suspicious = analyze_log(args.log, args.threshold)

    print("=== Summary (top IPs) ===")
    for ip, cnt in counter.most_common(20):
        print(f"{ip}: {cnt}")

    if suspicious:
        print("\n=== Suspicious IPs (threshold >= {}) ===".format(args.threshold))
        for ip, cnt in suspicious.items():
            print(f"{ip} - {cnt} failed attempts ⚠")
    else:
        print("\nNo suspicious IPs found.")

    if args.export:
        export_suspicious(suspicious)
        print(f"\nExported suspicious_ips.txt and suspicious_ips.csv")

    if args.show_table:
        if pd is None:
            print("\nPandas not installed. Install with: pip3 install pandas")
        else:
            df = pd.DataFrame(list(counter.items()), columns=["ip","failed_attempts"])
            print("\nPandas table (top 20):")
            print(df.sort_values("failed_attempts", ascending=False).head(20))

if __name__ == "__main__":
    main()
