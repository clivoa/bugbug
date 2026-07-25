"""Best-effort secret redaction over untrusted tool output."""

from hackbot.evidence.redact import redact_bytes


def test_redacts_authorization_and_cookie_headers():
    out = redact_bytes(b"Authorization: Bearer abc.def.ghi\r\nSet-Cookie: s=xyz\r\n")
    assert b"abc.def.ghi" not in out
    assert b"xyz" not in out
    assert b"[REDACTED]" in out


def test_redacts_known_token_shapes():
    assert b"AKIAIOSFODNN7EXAMPLE" not in redact_bytes(b"key AKIAIOSFODNN7EXAMPLE end")
    jwt = b"jwt eyJhbGciOiJI.eyJzdWIiOiI.SflKxwRJSMeK end"
    assert b"eyJhbGciOiJI" not in redact_bytes(jwt)
    assert b"[REDACTED]" in redact_bytes(jwt)


def test_redacts_secret_name_assignments_keeping_the_name():
    out = redact_bytes(b"password=hunter2 kept")
    assert b"hunter2" not in out
    assert b"password" in out and b"[REDACTED]" in out


def test_benign_text_is_unchanged():
    body = b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nlab-ok"
    assert redact_bytes(body) == body


def test_arbitrary_bytes_are_preserved():
    data = b"\xff\xfe binary \x00 body"
    assert redact_bytes(data) == data
