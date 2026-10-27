import json
import re
from pathlib import Path
from urllib.parse import unquote

from src.log_parser import parse_access_log

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
    entry = parse_access_log(line)

    if entry is not None:
        request = entry.target
        status = entry.status_code
    else:
        # Preserve compatibility with lines accepted by the old analyzer.
        request_match = re.search(r'"([^"]*)"', line)

        if not request_match:
            return []

        request = request_match.group(1)
        status_match = re.search(r'"[^"]*"\s+(\d{3})\s', line)
        status = int(status_match.group(1)) if status_match else None

    decoded_request = request

    for _ in range(2):
        normalized_request = unquote(decoded_request)

        if normalized_request == decoded_request:
            break

        decoded_request = normalized_request

    findings = []

    if any(
        pattern.search(decoded_request)
        for pattern in SQL_INJECTION_PATTERNS
    ):
        findings.append("possible SQL injection")

    if any(
        pattern.search(decoded_request)
        for pattern in XSS_PATTERNS
    ):
        findings.append("possible XSS")

    if any(
        pattern.search(decoded_request)
        for pattern in SCANNER_PATTERNS
    ):
        findings.append("possible scanner probe")

    if status is not None:
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

def summarize_findings(
    results: list[tuple[int, str, list[str]]],
) -> dict[str, int]:
    """Count how many times each finding appears."""
    summary = {}

    for _, _, findings in results:
        for finding in findings:
            summary[finding] = summary.get(finding, 0) + 1

    return summary

def export_results_json(
    results: list[tuple[int, str, list[str]]],
) -> str:
    """Convert analysis results into a JSON string."""
    data = [
        {
            "line_number": line_number,
            "log_line": log_line,
            "findings": findings,
        }
        for line_number, log_line, findings in results
    ]

    return json.dumps(data, indent=2, ensure_ascii=False)

def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(
        description="Find suspicious indicators in a web access log."
    )
    parser.add_argument("logfile", type=Path, help="Path to the access log")
    parser.add_argument(
        "--json",
        type=Path,
        metavar="OUTPUT_PATH",
        help="Write findings to a JSON file",
    )
    args = parser.parse_args()

    try:
        results = analyze_file(args.logfile)
    except OSError as error:
        parser.error(f"cannot read log file: {error}")

    if args.json is not None:
        if args.json.resolve() == args.logfile.resolve():
            parser.error("JSON output path must differ from input log file")

        try:
            args.json.write_text(
                export_results_json(results),
                encoding="utf-8",
            )
        except OSError as error:
            parser.error(f"cannot write JSON output: {error}")

        print(f"JSON results written to {args.json}")
        return

    if not results:
        print("No suspicious indicators found.")
        return

    print(f"Suspicious log lines: {len(results)}")

    summary = summarize_findings(results)

    print("\nFindings summary:")
    for finding, count in sorted(summary.items()):
        print(f"  {finding}: {count}")

    print("\nDetailed findings:")
    for line_number, line, findings in results:
        print(f"[Line {line_number}] {', '.join(findings)}")
        print(f"  {line}")



if __name__ == "__main__":
    main()