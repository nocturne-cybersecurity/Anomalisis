from typing import Set, List, Dict, Any

SAFE_PORTS: Set[int] = {
    20, 21,    # FTP
    22,         # SSH
    25,         # SMTP
    53,         # DNS
    80, 443,    # HTTP/HTTPS
    123,        # NTP
    143,        # IMAP
    389, 636,   # LDAP/LDAPS
    587,        # SMTP (submission)
    993,        # IMAPS
    995,        # POP3S
    1723,       # PPTP
    3306,       # MySQL
    3389,       # RDP
    5432,       # PostgreSQL
    8080,       # HTTP Proxy
    8443        # HTTPS Alternative
}

#Puertos críticos que requieren confirmación adicional
CRITICAL_PORTS: Set[int] = {
    22,    # SSH
    3389,  # RDP
    3306,  # MySQL
    5432   # PostgreSQL
}

def is_port_safe(port: int) -> bool:
    return port in SAFE_PORTS
def is_critical_port(port: int) -> bool:
    return port in CRITICAL_PORTS
def validate_port(port: int) -> bool:
    return 1 <= port <= 65535
def validate_ip(ip: str) -> bool:
    ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    cidr_pattern = r'^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$'
    import re
    return bool(re.match(ip_pattern, ip) or re.match(cidr_pattern, ip))
