
import re
from pathlib import Path
from urllib.parse import unquote

SQL_INJECTION_PATTERNS = [
    re.compile(r"\bunion\s+select\b", re.IGNORECASE),
    re.compile(r"\bor\b\s+\d+\s*=\s*\d+", re.IGNORECASE),
    re.compile(r"\bselect\b.+\bfrom\b", re.IGNORECASE),
]

XSS_PATTERNS = [
    re.compile(r"<\s*script\b", re.IGNORECASE),
    re.compile(r"javascript\s*:", re.IGNORECASE),
    re.compile(r"\bonerror\s*=", re.IGNORECASE),
]


SCANNER_PATTERNS = [
    re.compile(r"/\.env(?:\b|/|$)", re.IGNORECASE),
    re.compile(r"/wp-login\.php(?:\b|[?/]|$)", re.IGNORECASE),
    re.compile(r"/phpmyadmin(?:\b|/|$)", re.IGNORECASE),
]


def analyze_line(line: str) -> list[str]:
    """Return suspicious indicators found in one log line."""
    request_match = re.search(r'"([^"]*)"', line)
    findings = []

    if not request_match:
        return findings

    request = request_match.group(1)
    decoded_request = unquote(request)


    if any(pattern.search(decoded_request) for pattern in SQL_INJECTION_PATTERNS):
        findings.append("possible SQL injection")

    if any(pattern.search(decoded_request) for pattern in XSS_PATTERNS):
        findings.append("possible XSS")

    if any(pattern.search(decoded_request) for pattern in SCANNER_PATTERNS):
        findings.append("possible scanner probe")

    status_match = re.search(r'"[^"]*"\s+(\d{3})\s', line)

    if status_match:
        status = int(status_match.group(1))

        if 400 <= status <= 499:
            findings.append(f"HTTP client error ({status})")
        elif 500 <= status <= 599:
            findings.append(f"HTTP server error ({status})")

    return findings


def analyze_file(log_path: Path) -> list[tuple[int, str, list[str]]]:
    """Analyze a log file and return findings with line numbers."""
    results = []

    with log_path.open("r", encoding="utf-8", errors="replace") as log_file:
        for line_number, line in enumerate(log_file, start=1):
            findings = analyze_line(line)

            if findings:
                results.append((line_number, line.rstrip(), findings))

    return results

def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(
        description="Find suspicious indicators in a web access log."
    )
    parser.add_argument("logfile", type=Path, help="Path to the access log")
    args = parser.parse_args()

    try:
        results = analyze_file(args.logfile)
    except OSError as error:
        parser.error(f"cannot read log file: {error}")


    if not results:
        print("No suspicious indicators found.")
        return

    print(f"Suspicious log lines: {len(results)}")

    summary = {}

    for _, _, findings in results:
        for finding in findings:
            summary[finding] = summary.get(finding, 0) + 1

    print("\nFindings summary:")
    for finding, count in sorted(summary.items()):
        print(f"  {finding}: {count}")

    print("\nDetailed findings:")
    for line_number, line, findings in results:
        print(f"[Line {line_number}] {', '.join(findings)}")
        print(f"  {line}")


if __name__ == "__main__":
    main()
