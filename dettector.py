import re
from collections import defaultdict
from database import insert_detection

SQL_PATTERNS = [
    r"union.*select",
    r"select.*from",
    r"drop\s+table",
    r"or\s+1=1",
    r"--"
]

FAILED_LOGIN_PATTERNS = [
    r"failed password",
    r"authentication failure"
]

def detect_attacks(log_lines):
    ip_failures = defaultdict(int)
    suspicious_ips = set()

    for line in log_lines:
        ip_match = re.match(r"(\d+\.\d+\.\d+\.\d+)", line)
        if not ip_match:
            continue

        ip = ip_match.group(1)
        lower_line = line.lower()

        for pattern in SQL_PATTERNS:
            if re.search(pattern, lower_line):
                insert_detection(ip, "SQL_INJECTION", line)
                suspicious_ips.add(ip)

        for pattern in FAILED_LOGIN_PATTERNS:
            if re.search(pattern, lower_line):
                ip_failures[ip] += 1
                if ip_failures[ip] >= 5:
                    insert_detection(ip, "BRUTE_FORCE", line)
                    suspicious_ips.add(ip)

    return suspicious_ips
