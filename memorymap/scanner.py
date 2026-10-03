"""Secret and PII scanner for raw memory.

Memory is first reduced to printable strings (ASCII and UTF-16LE, the latter being how
Windows stores most text). Every pattern then runs once over the joined strings, and
candidates that have a checksum or structure go through a validator before being reported.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import os
import re
from bisect import bisect_right
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, List, Optional

SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}

MIN_STRING_LEN = 6
MAX_STRING_LEN = 65536
_ASCII_RUN = re.compile(rb"[\x20-\x7e\t]{%d,%d}" % (MIN_STRING_LEN, MAX_STRING_LEN))
_UTF16_RUN = re.compile(rb"(?:[\x20-\x7e]\x00){%d,%d}" % (MIN_STRING_LEN, MAX_STRING_LEN))


# --- validators ---------------------------------------------------------------------------------

def luhn_valid(number: str) -> bool:
    digits = [int(c) for c in number if c.isdigit()]
    if len(digits) < 12 or len(set(digits)) == 1:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2:
            d = d * 2 - 9 if d > 4 else d * 2
        total += d
    return total % 10 == 0


def _b64url_json(segment: str) -> Optional[dict]:
    try:
        raw = base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))
        value = json.loads(raw)
    except (binascii.Error, ValueError):
        return None
    return value if isinstance(value, dict) else None


def jwt_valid(token: str) -> bool:
    header, payload, _sig = token.split(".")
    head = _b64url_json(header)
    return head is not None and "alg" in head and _b64url_json(payload) is not None


_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def bitcoin_valid(address: str) -> bool:
    if address.startswith("bc1"):
        return True  # bech32 structure is already enforced by the regex
    n = 0
    for ch in address:
        idx = _B58.find(ch)
        if idx < 0:
            return False
        n = n * 58 + idx
    try:
        raw = n.to_bytes(25, "big")
    except OverflowError:
        return False
    return hashlib.sha256(hashlib.sha256(raw[:21]).digest()).digest()[:4] == raw[21:]


def ssn_valid(value: str) -> bool:
    area, group, serial = value.split("-")
    return area not in ("000", "666") and not area.startswith("9") and group != "00" and serial != "0000"


_PLACEHOLDERS = {"password", "passwd", "secret", "changeme", "example", "undefined", "redacted", "xxxxxxxx"}


def password_valid(value: str) -> bool:
    v = value.lower()
    looks_like_path = bool(re.match(r"[a-z]:[/\\]|[/\\]{1,2}[\w.-]", v))
    looks_like_code = any(c in value for c in "()[]{}")
    classes = sum(bool(re.search(p, value)) for p in ("[a-z]", "[A-Z]", "[0-9]", r"[^A-Za-z0-9]"))
    return (v not in _PLACEHOLDERS and len(set(v)) > 3 and classes >= 2
            and not looks_like_path and not looks_like_code
            and not v.startswith(("${", "{{", "%", "<", "$(")))


# --- patterns ------------------------------------------------------------------------------------

@dataclass(frozen=True)
class Pattern:
    id: str
    category: str
    severity: str
    regex: str
    validator: Optional[Callable[[str], bool]] = None
    group: int = 0
    sensitive: bool = True  # masked in output unless the user asks to reveal

    @property
    def compiled(self) -> "re.Pattern[str]":
        return _COMPILED[self.id]


PATTERNS: List[Pattern] = [
    Pattern("private_key", "Private key (PEM)", "CRITICAL",
            r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-----"),
    Pattern("aws_access_key", "AWS access key ID", "CRITICAL",
            r"\b(?:AKIA|ASIA|AROA|AIDA|AGPA|ANPA|ANVA|AIPA)[A-Z0-9]{16}\b"),
    Pattern("aws_secret_key", "AWS secret access key", "CRITICAL",
            r"(?i)aws[_\-. ]?secret[_\-. ]?(?:access[_\-. ]?)?key[\"' \t]*[:=][\"' \t]*([A-Za-z0-9/+=]{40})\b",
            group=1),
    Pattern("github_token", "GitHub token", "CRITICAL",
            r"\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{50,})\b"),
    Pattern("stripe_live_key", "Stripe live key", "CRITICAL", r"\b[sr]k_live_[0-9A-Za-z]{24,}\b"),
    Pattern("credit_card", "Payment card number", "CRITICAL",
            r"(?<![\d-])(?:4\d{12}(?:\d{3})?|5[1-5]\d{14}|2(?:2[2-9]\d|[3-6]\d\d|7[01]\d|720)\d{12}"
            r"|3[47]\d{13}|6(?:011|5\d\d)\d{12})(?!\d)",
            validator=luhn_valid),
    Pattern("jwt", "JSON Web Token", "HIGH",
            r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b", validator=jwt_valid),
    Pattern("bearer_token", "Bearer token", "HIGH",
            r"(?i)\bauthorization[\"']?[ \t]*[:=][ \t]*[\"']?bearer[ \t]+([A-Za-z0-9._~+/=-]{20,})", group=1),
    Pattern("slack_token", "Slack token", "HIGH", r"\bxox[abprs]-[0-9A-Za-z-]{10,}\b"),
    Pattern("google_api_key", "Google API key", "HIGH", r"\bAIza[0-9A-Za-z_\-]{35}\b"),
    Pattern("sendgrid_key", "SendGrid API key", "HIGH",
            r"\bSG\.[0-9A-Za-z_\-]{22}\.[0-9A-Za-z_\-]{43}\b"),
    Pattern("password_assignment", "Password assignment", "HIGH",
            r"""(?i)\b(?:password|passwd|pwd|secret)["']?[ \t]*[:=][ \t]*["']?([^\s"'&;,<>]{8,64})""",
            validator=password_valid, group=1),
    Pattern("connection_string", "Database connection string", "HIGH",
            r"(?i)\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|amqps?|mssql)"
            r"://[^\s:/@]+:[^\s@/]+@[^\s/]+"),
    Pattern("basic_auth_url", "Credentials in URL", "HIGH", r"(?i)\bhttps?://[^\s:/@]+:[^\s@/]+@[^\s/]+"),
    Pattern("ssn", "US Social Security number", "MEDIUM",
            r"(?<![\d-])\d{3}-\d{2}-\d{4}(?![\d-])", validator=ssn_valid),
    Pattern("email", "Email address", "MEDIUM",
            r"\b[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}\b"),
    Pattern("bitcoin_address", "Bitcoin address", "MEDIUM",
            r"\b(?:[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[ac-hj-np-z02-9]{11,71})\b", validator=bitcoin_valid),
    Pattern("stripe_test_key", "Stripe test key", "LOW", r"\b[sr]k_test_[0-9A-Za-z]{24,}\b"),
    Pattern("ethereum_address", "Ethereum address", "LOW", r"\b0x[a-fA-F0-9]{40}\b", sensitive=False),
    Pattern("url", "URL", "LOW", r"\bhttps?://[^\s\"'<>\\]{8,200}", sensitive=False),
    Pattern("ip_port", "IP address and port", "LOW",
            r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d):\d{2,5}\b", sensitive=False),
    Pattern("api_path", "Internal API path", "LOW",
            r"(?<![\w/])/api/v\d+/[A-Za-z0-9/_\-.]{4,}", sensitive=False),
]

_COMPILED = {p.id: re.compile(p.regex) for p in PATTERNS}
_PATTERN_BY_ID = {p.id: p for p in PATTERNS}


# --- findings ------------------------------------------------------------------------------------

def mask(value: str) -> str:
    """Keep enough of a secret to recognise it without exposing it."""
    if "@" in value and re.fullmatch(r"[^@\s]+@[^@\s]+", value):
        local, domain = value.split("@", 1)
        return f"{local[:1]}{'•' * min(len(local) - 1, 6)}@{domain}"
    if len(value) <= 8:
        return value[:1] + "•" * (len(value) - 1)
    head, tail = (4, 2) if len(value) > 14 else (2, 0)
    hidden = min(len(value) - head - tail, 12)
    return value[:head] + "•" * hidden + (value[-tail:] if tail else "")


def _fingerprint_key() -> bytes:
    """Per-machine secret used to fingerprint values.

    Snapshots store fingerprints instead of plaintext so they can be compared later without
    becoming a second copy of the secrets. A plain hash would be brute-forceable for
    structured values such as card numbers, hence the keyed HMAC.
    """
    global _KEY
    if _KEY is None:
        path = Path(os.environ.get("MEMORYMAP_KEY_FILE") or
                    Path(os.environ.get("LOCALAPPDATA", Path.home())) / "memorymap" / "fingerprint.key")
        try:
            _KEY = path.read_bytes()
        except FileNotFoundError:
            _KEY = os.urandom(32)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(_KEY)
    return _KEY


_KEY: Optional[bytes] = None


@dataclass
class Finding:
    pattern: str
    category: str
    severity: str
    value: str
    address: int
    count: int = 1
    encoding: str = "ascii"
    sensitive: bool = True

    @property
    def fingerprint(self) -> str:
        msg = f"{self.pattern}\0{self.value}".encode("utf-8", "replace")
        return hmac.new(_fingerprint_key(), msg, hashlib.sha256).hexdigest()[:20]

    def display(self, reveal: bool = False, max_len: int = 120) -> str:
        text = self.value if reveal or not self.sensitive else mask(self.value)
        return text if len(text) <= max_len else text[:max_len] + "…"

    def as_dict(self, reveal: bool = False) -> dict:
        return {
            "fp": self.fingerprint,
            "sensitive": self.sensitive,
            "pattern": self.pattern,
            "category": self.category,
            "severity": self.severity,
            "value": self.display(reveal),
            "length": len(self.value),
            "address": self.address,
            "count": self.count,
            "encoding": self.encoding,
        }


class SecretScanner:
    """Accumulates findings across chunks; identical values are merged and counted."""

    def __init__(self, min_severity: str = "LOW", patterns: Optional[List[Pattern]] = None):
        floor = SEVERITY_RANK[min_severity]
        self._patterns = [p for p in (patterns or PATTERNS) if SEVERITY_RANK[p.severity] >= floor]
        self._found: Dict[tuple, Finding] = {}

    def feed(self, data: bytes, base: int, core_len: Optional[int] = None) -> List["Finding"]:
        """Scan ``data`` mapped at ``base``; returns the findings seen for the first time.

        Matches starting at or beyond ``core_len`` are skipped (they belong to the next chunk).
        """
        created: List[Finding] = []
        core = len(data) if core_len is None else core_len
        strings: Dict[str, list] = {}  # text -> [first byte offset, multiplicity, encoding]

        for rx, enc in ((_ASCII_RUN, "ascii"), (_UTF16_RUN, "utf-16-le")):
            for m in rx.finditer(data):
                if m.start() >= core:
                    break
                text = m.group().decode(enc)
                entry = strings.get(text)
                if entry:
                    entry[1] += 1
                else:
                    strings[text] = [m.start(), 1, enc]
        if not strings:
            return created

        texts = list(strings)
        starts: List[int] = []
        pos = 0
        for t in texts:
            starts.append(pos)
            pos += len(t) + 1
        blob = "\n".join(texts)

        for pat in self._patterns:
            for m in pat.compiled.finditer(blob):
                value = m.group(pat.group)
                if not value or len(value) < 4 or (pat.validator and not pat.validator(value)):
                    continue
                idx = bisect_right(starts, m.start(pat.group)) - 1
                offset, mult, enc = strings[texts[idx]]
                key = (pat.id, value)
                existing = self._found.get(key)
                if existing:
                    existing.count += mult
                    continue
                char_pos = m.start(pat.group) - starts[idx]
                finding = Finding(
                    pattern=pat.id,
                    category=pat.category,
                    severity=pat.severity,
                    value=value,
                    address=base + offset + char_pos * (2 if enc == "utf-16-le" else 1),
                    count=mult,
                    encoding="utf-16" if enc == "utf-16-le" else "ascii",
                    sensitive=pat.sensitive,
                )
                self._found[key] = finding
                created.append(finding)
        return created

    def __len__(self) -> int:
        return len(self._found)

    def findings(self) -> List[Finding]:
        return sorted(self._found.values(),
                      key=lambda f: (-SEVERITY_RANK[f.severity], f.category, -f.count, f.address))

    def scan(self, data: bytes, base: int = 0) -> List[Finding]:
        """One-shot convenience wrapper."""
        self._found.clear()
        self.feed(data, base)
        return self.findings()


def pattern_info(pattern_id: str) -> Pattern:
    return _PATTERN_BY_ID[pattern_id]
