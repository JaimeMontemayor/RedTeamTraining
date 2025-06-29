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
        contador_sqli = 0
        contador_xss = 0
        contador_PT = 0
        contador_LF = 0
        for line in file:
            ip = extract_ip(line)
            if not ip:
                continue

            if "login failed" in line.lower():
                login_failures[ip] += 1
            
            if sql_injection.search(line):
                print(f"[SQL Injection] IP: {ip} -> {line.strip()}")
                contador_sqli += 1
            
            if xss_attack.search(line):
                print(f"[XSS] IP: {ip} -> {line.strip()}")
                contador_xss += 1
            
            if path_traversal.search(line):
                print(f"[Path Traversal] IP: {ip} -> {line.strip()}")
                contador_PT += 1
        print("\n***** FINAL RESULTS *****")
        print(f"Total SQLi detected: {contador_sqli}")
        print(f"Total XSS detected: {contador_xss}")
        print(f"Total path traversal detected: {contador_PT}")
        print(f"Total login failed more than 5 times detected: {contador_LF}")

    #Show IPs with 5 or more failed logins
    for ip, count in login_failures.items():
        if count > 5:
            print(f"IP: {ip} number of failed login attempts: {count}")
            contador_LF += 1


def extract_ip(line):
    parts = line.split(" ")
    if len(parts) > 0:
        return parts[0]
    return None




if __name__ == "__main__":
    log_analysis()
