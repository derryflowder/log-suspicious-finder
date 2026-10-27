from src.analyzer import (
    analyze_file,
    analyze_line,
    export_results_json,
    summarize_findings,
)


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

def test_detects_scanner_probe():
    line = '"GET /.env HTTP/1.1" 404 210'

    findings = analyze_line(line)

    assert "possible scanner probe" in findings
    assert "HTTP client error (404)" in findings

import subprocess
import sys


def test_cli_reports_missing_file():
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "src.analyzer",
            "samples/file_that_does_not_exist.log",
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode != 0
    assert "cannot read log file" in result.stderr

def test_normal_url_with_unrelated_script_text_is_not_flagged_as_xss():
    line = (
        '192.0.2.20 - - [27/Oct/2026:10:00:06 +0000] '
        '"GET /search?q=hello HTTP/1.1" 200 120 '
        '"<script>" "ExampleBrowser/1.0"'
    )

    findings = analyze_line(line)

    assert "possible XSS" not in findings

def test_xss_in_referer_does_not_flag_safe_request_target():
    line = (
        '192.0.2.20 - - [27/Oct/2026:10:00:06 +0000] '
        '"GET /index.html HTTP/1.1" 200 120 '
        '"<script>alert(1)</script>" "ExampleBrowser/1.0"'
    )

    findings = analyze_line(line)

    assert "possible XSS" not in findings
    assert findings == []

def test_analyze_file_returns_structured_results(tmp_path):
    log_file = tmp_path / "test.log"
    log_file.write_text(
        '192.0.2.12 - - [27/Oct/2026:10:00:03 +0000] '
        '"GET /search?q=%27%20OR%201%3D1 HTTP/1.1" 400 320\n',
        encoding="utf-8",
    )

    results = analyze_file(log_file)

    assert len(results) == 1

    line_number, original_line, findings = results[0]

    assert line_number == 1
    assert "GET /search" in original_line
    assert "possible SQL injection" in findings
    assert "HTTP client error (400)" in findings

def test_summarize_findings_counts_all_indicators():
    results = [
        (
            1,
            "GET /search?q=test",
            ["possible SQL injection", "HTTP client error (400)"],
        ),
        (
            2,
            "GET /admin",
            ["HTTP client error (403)"],
        ),
        (
            3,
            "GET /other",
            ["possible SQL injection"],
        ),
    ]

    summary = summarize_findings(results)

    assert summary == {
        "possible SQL injection": 2,
        "HTTP client error (400)": 1,
        "HTTP client error (403)": 1,
    }
    
def test_summarize_findings_returns_empty_dict_for_no_results():
    assert summarize_findings([]) == {}

def test_summarize_findings_does_not_modify_results():
    results = [
        (
            1,
            "GET /search?q=test",
            ["possible SQL injection"],
        )
    ]

    original_results = [
        (line_number, line, findings.copy())
        for line_number, line, findings in results
    ]

    summarize_findings(results)

    assert results == original_results

import json


def test_export_results_json_returns_valid_json():
    results = [
        (
            3,
            "GET /search?q=test",
            ["possible SQL injection", "HTTP client error (400)"],
        )
    ]

    exported = export_results_json(results)
    data = json.loads(exported)

    assert data == [
        {
            "line_number": 3,
            "log_line": "GET /search?q=test",
            "findings": [
                "possible SQL injection",
                "HTTP client error (400)",
            ],
        }
    ]

def test_cli_exports_json_to_file(tmp_path):
    import json
    import subprocess
    import sys

    log_file = tmp_path / "access.log"
    output_file = tmp_path / "results.json"

    log_file.write_text(
        '192.0.2.12 - - [27/Oct/2026:10:00:03 +0000] '
        '"GET /search?q=%27%20OR%201%3D1 HTTP/1.1" 400 320\n',
        encoding="utf-8",
    )

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "src.analyzer",
            str(log_file),
            "--json",
            str(output_file),
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0
    assert output_file.exists()

    data = json.loads(output_file.read_text(encoding="utf-8"))
    assert len(data) == 1
    assert data[0]["line_number"] == 1
    assert "possible SQL injection" in data[0]["findings"]


def test_cli_exports_empty_results_to_json(tmp_path):
    import json
    import subprocess
    import sys

    log_file = tmp_path / "access.log"
    output_file = tmp_path / "results.json"
    log_file.write_text(
        '192.0.2.10 - - [27/Oct/2026:10:00:01 +0000] '
        '"GET /index.html HTTP/1.1" 200 1200\n',
        encoding="utf-8",
    )

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "src.analyzer",
            str(log_file),
            "--json",
            str(output_file),
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0
    assert output_file.exists()
    assert json.loads(output_file.read_text(encoding="utf-8")) == []


def test_cli_reports_json_write_error(tmp_path):
    import subprocess
    import sys

    log_file = tmp_path / "access.log"
    output_file = tmp_path / "missing" / "results.json"
    log_file.write_text(
        '192.0.2.10 - - [27/Oct/2026:10:00:01 +0000] '
        '"GET /index.html HTTP/1.1" 200 1200\n',
        encoding="utf-8",
    )

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "src.analyzer",
            str(log_file),
            "--json",
            str(output_file),
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode != 0
    assert "cannot write JSON output" in result.stderr
    assert "Traceback" not in result.stderr


def test_cli_does_not_overwrite_input_log_with_json(tmp_path):
    import subprocess
    import sys

    log_file = tmp_path / "access.log"
    original_content = (
        '192.0.2.12 - - [27/Oct/2026:10:00:03 +0000] '
        '"GET /search?q=%27%20OR%201%3D1 HTTP/1.1" 400 320\n'
    )
    log_file.write_text(original_content, encoding="utf-8")

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "src.analyzer",
            str(log_file),
            "--json",
            str(log_file),
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode != 0
    assert "JSON output path must differ from input log file" in result.stderr
    assert log_file.read_text(encoding="utf-8") == original_content


def test_cli_help_includes_json_option():
    import subprocess
    import sys

    result = subprocess.run(
        [sys.executable, "-m", "src.analyzer", "--help"],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0
    assert "--json OUTPUT_PATH" in result.stdout
    assert "Write findings to a JSON file" in result.stdout

def test_detects_double_encoded_sql_injection():
    line = '"GET /search?q=%2527%2520OR%25201%253D1 HTTP/1.1" 200 100'

    findings = analyze_line(line)

    assert "possible SQL injection" in findings


def test_detects_double_encoded_xss():
    line = '"GET /search?q=%253Cscript%253E HTTP/1.1" 200 100'

    findings = analyze_line(line)

    assert "possible XSS" in findings


def test_does_not_analyze_user_agent_as_request():
    line = (
        '192.0.2.20 - - [27/Oct/2026:10:00:06 +0000] '
        '"GET /index.html HTTP/1.1" 200 120 '
        '"<script>alert(1)</script>" "ExampleBrowser/1.0"'
    )

    findings = analyze_line(line)

    assert "possible XSS" not in findings
