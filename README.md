# Simple Log Suspicious Finder

A small Python command-line tool that scans web access logs for potentially suspicious requests and HTTP errors.

## Features

- Detects heuristic indicators of possible SQL injection.
- Detects heuristic indicators of possible cross-site scripting (XSS).
- Flags requests to common scanner targets, such as `/.env`, `/wp-login.php`, and `/phpmyadmin`.
- Reports HTTP client errors (`4xx`) and server errors (`5xx`).
- Prints a summary and detailed findings with line numbers.
- Includes automated tests using pytest.

## Requirements

- Python 3.14 or another compatible Python 3 version.
- pip.

## Setup

Clone or download the project, then open a terminal in the project directory.

Create a virtual environment:

```powershell
python -m venv .venv
```

Install the development tools:

```powershell
.\.venv\Scripts\python.exe -m pip install pytest ruff
```

## Usage

Run the analyzer against the included sample log:

```powershell
.\.venv\Scripts\python.exe -m src.analyzer samples/access.log
```

The output includes a summary of findings and details for each flagged log line.

## Tests

Run the automated tests:

```powershell
.\.venv\Scripts\python.exe -m pytest tests/ -v
```

Run the code-quality check:

```powershell
.\.venv\Scripts\python.exe -m ruff check src tests
```

## Limitations

This tool uses simple pattern matching, not a full attack-detection engine. A finding is an indicator for further investigation, not proof of an attack. False positives and false negatives are possible. HTTP status codes alone do not establish malicious activity.

Use it with logs you are authorized to analyze. The included sample data is synthetic.

## Project status

Learning project under active development.
