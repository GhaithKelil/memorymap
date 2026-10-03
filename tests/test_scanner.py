import base64
import json

from memorymap.scanner import SecretScanner, bitcoin_valid, luhn_valid, mask


def scan(data: bytes, **kw):
    return SecretScanner(**kw).scan(data)


def names(findings):
    return {f.pattern for f in findings}


def test_card_requires_valid_luhn():
    assert "credit_card" in names(scan(b"card=4111111111111111 "))
    assert "credit_card" not in names(scan(b"card=4111111111111112 "))
    assert not luhn_valid("4444444444444444")  # repeated digits are not a card


def test_jwt_must_decode():
    seg = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()  # noqa: E731
    token = f"{seg({'alg': 'HS256'})}.{seg({'sub': '1'})}.c2lnbmF0dXJlLWJ5dGVz"
    assert "jwt" in names(scan(token.encode()))
    assert "jwt" not in names(scan(b"eyJnotbase64json!!.eyJalsonotjson!!!.c2lnbmF0dXJlLWJ5dGVz"))


def test_finds_utf16_strings():
    found = scan("AKIAIOSFODNN7EXAMPLE".encode("utf-16-le"))
    assert [f.encoding for f in found if f.pattern == "aws_access_key"] == ["utf-16"]


def test_address_accounts_for_utf16_width():
    data = b"\x00" * 10 + "password = Tr0ub4dor&3xample".encode("utf-16-le")
    f = next(f for f in SecretScanner().scan(data, base=0x1000) if f.pattern == "password_assignment")
    assert f.address == 0x1000 + 10 + len("password = ") * 2


def test_identical_values_are_merged_and_counted():
    found = scan(b"AKIAIOSFODNN7EXAMPLE\x00" * 3 + b"AKIAIOSFODNN7EXAMPLE")
    keys = [f for f in found if f.pattern == "aws_access_key"]
    assert len(keys) == 1 and keys[0].count == 4


def test_password_rejects_placeholders_and_paths():
    assert "password_assignment" not in names(scan(b"password = changeme "))
    assert "password_assignment" not in names(scan(b"password=C:/Users/bob/vault.db "))
    assert "password_assignment" in names(scan(b"password = Tr0ub4dor&3xample "))


def test_bitcoin_checksum():
    assert bitcoin_valid("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2")
    assert not bitcoin_valid("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN3")


def test_min_severity_filters_low_findings():
    data = b"visit https://example.com/some/path now"
    assert "url" in names(scan(data))
    assert "url" not in names(scan(data, min_severity="HIGH"))


def test_matches_past_core_len_belong_to_the_next_chunk():
    data = b"AKIAIOSFODNN7EXAMPLE" + b"\x00" * 600 + b"ASIAIOSFODNN7EXAMPLE"
    s = SecretScanner()
    s.feed(data, 0, core_len=100)
    assert [f.value for f in s.findings()] == ["AKIAIOSFODNN7EXAMPLE"]


def test_masking_hides_most_of_the_value():
    secret = "AKIAIOSFODNN7EXAMPLE"
    masked = mask(secret)
    assert masked.startswith("AKIA") and secret not in masked and "•" in masked
    assert mask("jane.doe@example.com").endswith("@example.com")


def test_display_masks_sensitive_but_not_urls():
    f = scan(b"AKIAIOSFODNN7EXAMPLE https://example.com/path/x")
    by = {x.pattern: x for x in f}
    assert by["aws_access_key"].display() != by["aws_access_key"].value
    assert by["aws_access_key"].display(reveal=True) == by["aws_access_key"].value
    assert by["url"].display() == by["url"].value


def test_fingerprint_is_stable_and_hides_value():
    a = scan(b"AKIAIOSFODNN7EXAMPLE")[0]
    b = scan(b"zzzz AKIAIOSFODNN7EXAMPLE zzzz")[0]
    assert a.fingerprint == b.fingerprint
    assert "AKIA" not in a.fingerprint
    assert a.fingerprint != scan(b"ASIAIOSFODNN7EXAMPLE")[0].fingerprint
