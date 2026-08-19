import re

SUSPICIOUS_UA_PATTERNS = [
    r"sqlmap",
    r"nmap",
    r"nikto",
    r"dirbuster",
    r"gobuster",
    r"zgrab",
    r"masscan",
    r"python-requests",
]

SENSITIVE_PATH_MARKERS = ("env", "aws", "git", "config", "secret", "iam", "credentials", "settings")


def sanitize_input(text: str) -> str:
    return "".join(char for char in text if char.isprintable())[:500]


def is_suspicious_ua(user_agent: str) -> bool:
    return any(re.search(pattern, user_agent, re.IGNORECASE) for pattern in SUSPICIOUS_UA_PATTERNS)


def touches_sensitive_path(path_lower: str) -> bool:
    return any(marker in path_lower for marker in SENSITIVE_PATH_MARKERS)
