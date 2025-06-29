import re
from collections import defaultdict

#Log file path
LOG_PATH = "fake_access.log"

#Diccionario para IPs sospechosas
ips_sus = defaultdict(int)

#Regular expressions for SQLi attacks
sql_injection = re.compile(r"""
    (
        \bOR\b\s+1=1                             # Boolean logic like OR 1=1
        |
        UNION\s+SELECT                           # UNION SELECT attack
        |
        SELECT\s+\w+\s+FROM\s+\w+                # SELECT ... FROM ...
        |
        INSERT\s+INTO\s+\w+\s+VALUES             # INSERT attack
        |
        DROP\s+TABLE\s+\w+                       # DROP TABLE
        |
        ['"][\s\w]*['"]\s*(--)                   # Quotation marks + comments
    )                               
    """, re.IGNORECASE | re.VERBOSE)


xss_attack = re.compile(r"<script>|%3Cscript%3E|onerror|alert\(")
path_traversal = re.compile(r"\.\./|\.\.\\")
login_failures = defaultdict(int)

#Functions
def log_analysis():
    with open(LOG_PATH, "r") as file:
        for line in file:
            ip = extract_ip(line)
            if not ip:
                continue

            if "login failed" in line.lower():
                login_failures[ip] += 1
            
            if sql_injection.search(line):
                print(f"[SQL Injection] IP: {ip} -> {line.strip()}")
            
            if xss_attack.search(line):
                print(f"[XSS] IP: {ip} -> {line.strip()}")
            
            if path_traversal.search(line):
                print(f"[Path Traversal] IP: {ip} -> {line.strip()}")

#Show IPs with 5 or more failed logins
print("\n Possible brute force attempts:")
for ip, count in login_failures.items():
    if count > 5:
        print(f"IP: {ip} number of failed login attempts: {count}")

def extract_ip(line):
    parts = line.split(" ")
    if len(parts) > 0:
        return parts[0]
    return None

if __name__ == "__main__":
    log_analysis()
