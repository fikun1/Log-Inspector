import re
import argparse 
from collections import defaultdict
from pathlib import Path

IP_PATTERN = re.compile(
    r'\b('
    r'(25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})\.){3}'
    r'(25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})\b'
)

FAILED_LOGIN_PATTERNS = [
    r'Failed password',
    r'authentication failure'
]

SENSITIVE_PATHS = ['/admin', '/wp-login', '/login', '/config']
def parse_args():
    parser = argparse.ArgumentParser(description="Log Inspector – Detect suspicious log activity.")
    parser.add_argument("logfile", type=str, help="Path to log file (e.g., auth.log or access.log)")
    parser.add_argument("--sensitive-paths", nargs="*", default=SENSITIVE_PATHS,
                        help="Custom sensitive paths to monitor (optional)")
    return parser.parse_args()

def inspect_log(file_path, sensitive_paths):
    failed_logins = defaultdict(int)
    sensitive_hits = defaultdict(int)
    flagged_entries = []

    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            ip_match = IP_PATTERN.search(line)
            ip = ip_match.group(0) if ip_match else None

            if any(re.search(p, line, re.IGNORECASE) for p in FAILED_LOGIN_PATTERNS):
                if ip:
                    failed_logins[ip] += 1
                    flagged_entries.append(("FAILED_LOGIN", ip, line.strip()))

            for path in sensitive_paths:
                if path in line and ip:
                    sensitive_hits[ip] += 1
                    flagged_entries.append(("SENSITIVE_PATH", ip, line.strip()))

    return failed_logins, sensitive_hits, flagged_entries