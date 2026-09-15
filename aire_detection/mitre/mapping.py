"""
A small, curated registry of MITRE ATT&CK (Enterprise) technique IDs
actually used by the detection rules in this engine.

Every ID here is a real, published ATT&CK technique/sub-technique.
Rules reference these by ID only; this module is the single source
of truth so an invalid ID is a hard failure caught by tests.
"""

ATTACK_TECHNIQUES = {
    "T1110": "Brute Force",
    "T1110.001": "Brute Force: Password Guessing",
    "T1110.003": "Brute Force: Password Spraying",
    "T1046": "Network Service Discovery",
    "T1595": "Active Scanning",
    "T1595.001": "Active Scanning: Scanning IP Blocks",
    "T1059": "Command and Scripting Interpreter",
    "T1059.001": "Command and Scripting Interpreter: PowerShell",
    "T1059.003": "Command and Scripting Interpreter: Windows Command Shell",
    "T1059.005": "Command and Scripting Interpreter: Visual Basic",
    "T1027": "Obfuscated Files or Information",
    "T1027.010": "Obfuscated Files or Information: Command Obfuscation",
    "T1140": "Deobfuscate/Decode Files or Information",
    "T1105": "Ingress Tool Transfer",
    "T1071": "Application Layer Protocol",
    "T1071.001": "Application Layer Protocol: Web Protocols",
    "T1071.004": "Application Layer Protocol: DNS",
    "T1218": "System Binary Proxy Execution",
    "T1218.010": "System Binary Proxy Execution: Regsvr32",
    "T1218.011": "System Binary Proxy Execution: Rundll32",
    "T1218.005": "System Binary Proxy Execution: Mshta",
    "T1218.002": "System Binary Proxy Execution: Control Panel",
    "T1553": "Subvert Trust Controls",
    "T1553.005": "Subvert Trust Controls: Mark-of-the-Web Bypass",
    "T1204": "User Execution",
    "T1204.002": "User Execution: Malicious File",
    "T1566": "Phishing",
    "T1566.001": "Phishing: Spearphishing Attachment",
    "T1053": "Scheduled Task/Job",
    "T1053.005": "Scheduled Task/Job: Scheduled Task",
    "T1543": "Create or Modify System Process",
    "T1543.003": "Create or Modify System Process: Windows Service",
    "T1547": "Boot or Logon Autostart Execution",
    "T1547.001": "Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder",
    "T1068": "Exploitation for Privilege Escalation",
    "T1548": "Abuse Elevation Control Mechanism",
    "T1562": "Impair Defenses",
    "T1562.001": "Impair Defenses: Disable or Modify Tools",
    "T1070": "Indicator Removal",
    "T1070.001": "Indicator Removal: Clear Windows Event Logs",
    "T1070.004": "Indicator Removal: File Deletion",
    "T1041": "Exfiltration Over C2 Channel",
    "T1567": "Exfiltration Over Web Service",
    "T1560": "Archive Collected Data",
    "T1560.001": "Archive Collected Data: Archive via Utility",
    "T1190": "Exploit Public-Facing Application",
    "T1595.002": "Active Scanning: Vulnerability Scanning",
    "T1136": "Create Account",
    "T1136.001": "Create Account: Local Account",
    "T1021": "Remote Services",
    "T1021.001": "Remote Services: Remote Desktop Protocol",
    "T1021.002": "Remote Services: SMB/Windows Admin Shares",
    "T1018": "Remote System Discovery",
}


def is_valid_technique(technique_id: str) -> bool:
    return technique_id in ATTACK_TECHNIQUES


def technique_name(technique_id: str) -> str:
    return ATTACK_TECHNIQUES.get(technique_id, "UNKNOWN")


def validate_techniques(technique_ids) -> None:
    """Raise ValueError if any technique ID is not in the curated registry."""
    for t in technique_ids:
        if not is_valid_technique(t):
            raise ValueError(f"Invalid or unregistered MITRE ATT&CK technique ID: {t}")
