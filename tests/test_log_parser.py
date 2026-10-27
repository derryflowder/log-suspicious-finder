from src.log_parser import parse_access_log


def test_parses_common_log_format():
    line = (
        '192.0.2.10 - - [27/Oct/2026:10:00:01 +0000] '
        '"GET /index.html HTTP/1.1" 200 1200'
    )

    entry = parse_access_log(line)

    assert entry is not None
    assert entry.client_ip == "192.0.2.10"
    assert entry.timestamp == "27/Oct/2026:10:00:01 +0000"
    assert entry.method == "GET"
    assert entry.target == "/index.html"
    assert entry.http_version == "1.1"
    assert entry.status_code == 200
    assert entry.response_size == 1200
    assert entry.referer is None
    assert entry.user_agent is None


def test_parses_combined_log_format():
    line = (
        '192.0.2.20 - - [27/Oct/2026:10:00:06 +0000] '
        '"GET /search?q=hello HTTP/1.1" 200 120 '
        '"https://example.com/" "ExampleBrowser/1.0"'
    )

    entry = parse_access_log(line)

    assert entry is not None
    assert entry.target == "/search?q=hello"
    assert entry.referer == "https://example.com/"
    assert entry.user_agent == "ExampleBrowser/1.0"


def test_parses_unknown_response_size():
    line = (
        '192.0.2.10 - - [27/Oct/2026:10:00:01 +0000] '
        '"GET /index.html HTTP/1.1" 200 -'
    )

    entry = parse_access_log(line)

    assert entry is not None
    assert entry.response_size is None


def test_rejects_malformed_log_line():
    assert parse_access_log("this is not a valid access log entry") is None


def test_rejects_malformed_http_request():
    line = (
        '192.0.2.10 - - [27/Oct/2026:10:00:01 +0000] '
        '"GET /index.html" 200 1200'
    )

    assert parse_access_log(line) is None


def test_does_not_confuse_referer_with_request_target():
    line = (
        '192.0.2.20 - - [27/Oct/2026:10:00:06 +0000] '
        '"GET /index.html HTTP/1.1" 200 120 '
        '"<script>alert(1)</script>" "ExampleBrowser/1.0"'
    )

    entry = parse_access_log(line)

    assert entry is not None
    assert entry.target == "/index.html"
    assert entry.referer == "<script>alert(1)</script>"

def test_parses_combined_log_with_extra_quoted_field():
    line = (
        '192.0.2.30 - - [27/Oct/2026:10:00:06 +0000] '
        '"GET /product/123 HTTP/1.1" 404 120 '
        '"-" "ExampleBot/1.0" "-"'
    )

    entry = parse_access_log(line)

    assert entry is not None
    assert entry.target == "/product/123"
    assert entry.status_code == 404
    assert entry.referer == "-"
    assert entry.user_agent == "ExampleBot/1.0"
