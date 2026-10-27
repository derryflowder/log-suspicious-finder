# Simple Log Suspicious Finder

A Python tool for analyzing web access logs and identifying potentially suspicious requests and HTTP errors. Includes both a command-line interface (CLI) and a web interface built with Streamlit.

## Features

- Detects heuristic indicators of possible SQL injection.
- Detects heuristic indicators of cross-site scripting (XSS).
- Flags requests to common scanner targets, such as `/.env`, `/wp-login.php`, and `/phpmyadmin`.
- Identifies HTTP client errors (`4xx`) and server errors (`5xx`).
- Displays a summary and detailed findings with line numbers.
- Exports analysis results to JSON.
- Provides an interactive web interface for uploading and analyzing log files.
- Includes automated tests using pytest and code-quality checks with Ruff.

## Requirements

- Python 3.14 or another compatible Python 3 version.
- pip.

## Setup

Clone or download the repository and open a terminal in the project directory.

Create a virtual environment:

```powershell
python -m venv .venv
```

Install the required dependencies:

```powershell
.\.venv\Scripts\python.exe -m pip install streamlit pytest ruff
```

## Usage

### Command-line interface

Analyze the included sample log:

```powershell
.\.venv\Scripts\python.exe -m src.analyzer samples/access.log
```

Export the findings to JSON:

```powershell
.\.venv\Scripts\python.exe -m src.analyzer samples/access.log --json results.json
```

### Web interface

Start the Streamlit application:

```powershell
.\.venv\Scripts\python.exe -m streamlit run app.py
```

Open the local URL printed in the terminal. Upload a `.log` or `.txt` file and select **Analyze log** to view the results. You can download the findings as a JSON file.

## Tests

Run the automated test suite:

```powershell
.\.venv\Scripts\python.exe -m pytest tests/ -v
```

Run Ruff:

```powershell
.\.venv\Scripts\python.exe -m ruff check src tests app.py
```

## Limitations

This tool uses simple pattern matching rather than a comprehensive attack-detection engine. Findings are indicators for further investigation, not proof of an attack. False positives and false negatives are possible, and HTTP status codes alone do not establish malicious activity.

Use this tool only with logs you are authorized to analyze. The included sample data is synthetic.

## Project Status

Learning project under active development.
