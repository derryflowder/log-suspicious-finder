
from src.analyzer import analyze_line


def test_normal_request_has_no_findings():
    line = '"GET /index.html HTTP/1.1" 200 1200'

    assert analyze_line(line) == []


def test_detects_sql_injection():
    line = '"GET /search?q=%27%20OR%201%3D1 HTTP/1.1" 400 320'

    findings = analyze_line(line)

    assert "possible SQL injection" in findings
    assert "HTTP client error (400)" in findings


def test_detects_xss():
    line = '"GET /<script>alert(1)</script> HTTP/1.1" 404 210'

    findings = analyze_line(line)

    assert "possible XSS" in findings
    assert "HTTP client error (404)" in findings


def test_detects_server_error():
    line = '"GET /page HTTP/1.1" 500 100'

    assert "HTTP server error (500)" in analyze_line(line)

def test_empty_line_has_no_findings():
    assert analyze_line("") == []


def test_malformed_line_has_no_findings():
    assert analyze_line("this is not a valid access log entry") == []


def test_encoded_xss_is_detected():
    line = '"GET /search?q=%3Cscript%3E HTTP/1.1" 200 100'

    findings = analyze_line(line)

    assert "possible XSS" in findings
