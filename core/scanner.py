import re
from dataclasses import dataclass
from typing import List, Tuple


@dataclass
class Finding:
    category:     str
    severity:     str
    match:        str
    offset:       int
    region_base:  int
    pattern_name: str

    @property
    def address(self) -> int:
        return self.region_base + self.offset

    def truncated_match(self, max_len: int = 80) -> str:
        if len(self.match) > max_len:
            return self.match[:max_len] + "…"
        return self.match


# (pattern_name, category, severity, regex_pattern)
SECRET_PATTERNS: List[Tuple[str, str, str, str]] = [
    (
        "jwt_token",
        "JWT Token",
        "CRITICAL",
        r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
    ),
    (
        "private_key_pem",
        "Private Key (PEM)",
        "CRITICAL",
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
    ),
    (
        "aws_access_key",
        "AWS Access Key",
        "CRITICAL",
        r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}",
    ),
    (
        "aws_secret_key",
        "AWS Secret Key",
        "CRITICAL",
        r"(?i)aws[_\-\s]?secret[_\-\s]?(?:access[_\-\s]?)?key[\s:=]+[A-Za-z0-9/+]{40}",
    ),
    (
        "github_token",
        "GitHub Token",
        "CRITICAL",
        r"gh[pousr]_[A-Za-z0-9_]{36,}",
    ),
    (
        "google_api_key",
        "Google API Key",
        "HIGH",
        r"AIza[0-9A-Za-z\-_]{35}",
    ),
    (
        "slack_token",
        "Slack Token",
        "HIGH",
        r"xox[baprs]-[0-9A-Za-z\-]{10,}",
    ),
    (
        "stripe_key",
        "Stripe Key",
        "HIGH",
        r"sk_(?:live|test)_[0-9A-Za-z]{24,}",
    ),
    (
        "sendgrid_key",
        "SendGrid API Key",
        "HIGH",
        r"SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}",
    ),
    (
        "heroku_api_key",
        "Heroku API Key",
        "HIGH",
        r"(?i)heroku[_\-\s]?api[_\-\s]?key[\s:=]+[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
    ),
    (
        "password_assignment",
        "Password (Plaintext)",
        "HIGH",
        r'(?i)(?:password|passwd|pwd|secret)["\s]*[:=]["\\s]*([^\s"\']{8,})',
    ),
    (
        "connection_string",
        "DB Connection String",
        "HIGH",
        r"(?i)(?:mysql|postgresql|mongodb|redis|sqlite):\/\/[^:\s]+:[^@\s]+@[^\s]+",
    ),
    (
        "basic_auth_url",
        "Basic Auth in URL",
        "HIGH",
        r"https?:\/\/[^:\s]+:[^@\s]+@[^\s/]+",
    ),
    (
        "ip_with_port",
        "Host:Port",
        "LOW",
        r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?):[0-9]{2,5}\b",
    ),
    (
        "email_address",
        "Email Address",
        "MEDIUM",
        r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
    ),
    (
        "credit_card",
        "Credit Card Number",
        "CRITICAL",
        r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b",
    ),
    (
        "ssn",
        "Social Security Number",
        "CRITICAL",
        r"\b[0-9]{3}-[0-9]{2}-[0-9]{4}\b",
    ),
    (
        "url_http",
        "URL (HTTP/S)",
        "LOW",
        r"https?://[^\s\"'<>]{8,}",
    ),
    (
        "internal_api_path",
        "Internal API Path",
        "LOW",
        r"/api/v[0-9]+/[a-zA-Z0-9/_\-]{4,}",
    ),
    (
        "bitcoin_address",
        "Bitcoin Address",
        "HIGH",
        r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b",
    ),
    (
        "ethereum_address",
        "Ethereum Address",
        "HIGH",
        r"\b0x[a-fA-F0-9]{40}\b",
    ),
]

_COMPILED = [
    (name, category, severity, re.compile(pattern.encode("utf-8", errors="ignore"), re.MULTILINE))
    for name, category, severity, pattern in SECRET_PATTERNS
]


class SecretScanner:
    def __init__(self, min_severity: str = "LOW"):
        self.min_severity = min_severity
        self._severity_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}

    def _severity_ok(self, severity: str) -> bool:
        return self._severity_rank.get(severity, 0) >= self._severity_rank.get(self.min_severity, 1)

    def scan_regions(self, regions) -> List[Finding]:
        all_findings: List[Finding] = []
        seen: set = set()

        for region in regions:
            if not region.data:
                continue
            for f in self._scan_bytes(region.data, region.base_address):
                key = (f.category, f.match[:60])
                if key not in seen:
                    seen.add(key)
                    all_findings.append(f)

        all_findings.sort(key=lambda f: self._severity_rank.get(f.severity, 0), reverse=True)
        return all_findings

    def _scan_bytes(self, data: bytes, base_addr: int) -> List[Finding]:
        findings: List[Finding] = []
        for name, category, severity, pattern in _COMPILED:
            if not self._severity_ok(severity):
                continue
            for m in pattern.finditer(data):
                try:
                    match_str = m.group(0).decode("utf-8", errors="replace").strip()
                except Exception:
                    continue
                if len(match_str) < 4:
                    continue
                findings.append(Finding(
                    category     = category,
                    severity     = severity,
                    match        = match_str,
                    offset       = m.start(),
                    region_base  = base_addr,
                    pattern_name = name,
                ))
        return findings
