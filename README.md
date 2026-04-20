# AccuScanner

AccuScanner is a defensive security assessment tool built in Python. It can run network and web scans, local code scans, and read-only database posture checks, then export JSON and HTML reports.

## What It Does

- Network and service scanning with `nmap`
- Web application review with passive crawling and optional browser-assisted discovery
- Local code scanning for secrets, insecure patterns, framework misconfigurations, file-handling issues, and dependency manifest risks
- Read-only database posture scanning for PostgreSQL, MySQL, and MSSQL
- JSON and HTML report generation
- Interactive launcher for guided usage

## Current Scan Modes

- `quick`
- `full`
- `web`
- `code-scan`
- `db-scan`

## Install

### Ubuntu

```bash
sudo apt update
sudo apt install -y python3 python3-venv nmap
git clone <repo-url>
cd AccuScanner
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -e .
```

Or use the convenience file:

```bash
pip install -r requirements.txt
```

### Windows

1. Install Python 3.11+
2. Install Nmap for Windows
3. Clone the repo
4. Open PowerShell in the repo root

```powershell
py -3 -m venv .venv
.venv\Scripts\Activate.ps1
pip install --upgrade pip
pip install -e .
```

Or:

```powershell
pip install -r requirements.txt
```

If `nmap.exe` is not on `PATH`:

```powershell
$env:NMAP_PATH="C:\Program Files (x86)\Nmap\nmap.exe"
```

## Optional Extras

Browser-assisted web scanning:

```bash
pip install -e ".[browser]"
python -m playwright install chromium
```

Or:

```bash
pip install -r requirements-browser.txt
python -m playwright install chromium
```

Database scanning:

```bash
pip install -e ".[database]"
```

Or:

```bash
pip install -r requirements-database.txt
```

## Important Install Note

This project uses `pyproject.toml` as the source of truth for Python dependencies. The `requirements*.txt` files are convenience wrappers for cloning and installing from the repo root.

Use:

```bash
pip install -e .
```

Or use:

```bash
pip install -r requirements.txt
```

Then add optional extras only when needed:

- `.[browser]`
- `.[database]`
- `requirements-browser.txt`
- `requirements-database.txt`

System tools like `nmap` still need to be installed separately.

## Quick Start

Interactive launcher:

```bash
python -m accuscanner
```

Direct CLI help:

```bash
python -m accuscanner --help
python -m accuscanner scan --help
python -m accuscanner code-scan --help
python -m accuscanner db-scan --help
```

## Common Commands

Quick scan:

```bash
python -m accuscanner scan 192.168.1.10 --mode quick --timestamped-dir
```

Full scan:

```bash
python -m accuscanner scan 10.0.0.0/24 --mode full --timestamped-dir
```

Web scan:

```bash
python -m accuscanner scan https://app.internal.example --mode web --timestamped-dir
```

Browser-assisted web scan:

```bash
python -m accuscanner scan https://app.internal.example --mode web --browser-assisted --browser-max-pages 6 --timestamped-dir
```

Authenticated web session scan:

```bash
python -m accuscanner scan https://app.internal.example --mode web --web-cookie "session=abc123" --web-header "Authorization: Bearer ey..." --browser-assisted --timestamped-dir
```

Code scan:

```bash
python -m accuscanner code-scan /path/to/repo --timestamped-dir
```

PostgreSQL scan:

```bash
python -m accuscanner db-scan --db-type postgres --host db.internal --port 5432 --database appdb --user audit --password "secret" --timestamped-dir
```

MySQL scan:

```bash
python -m accuscanner db-scan --db-type mysql --host db.internal --port 3306 --database appdb --user audit --password "secret" --timestamped-dir
```

MSSQL scan:

```bash
python -m accuscanner db-scan --db-type mssql --host sql.internal --port 1433 --database appdb --user audit --password "secret" --timestamped-dir
```

## Interactive Menu

Current top-level launcher options:

1. Simple mode
2. Advanced mode
3. Custom mode
4. Code scan
5. Database scan
6. Exit

## Web Scanning

AccuScanner web scanning includes:

- security header checks
- cookie flag checks
- sensitive path checks
- admin/login surface detection
- passive same-host crawling
- query/form/script inventory
- browser-assisted rendered discovery
- HTML attack-surface reporting

Browser-assisted mode adds:

- rendered links and forms
- limited SPA-style route discovery
- fetch/XHR request capture
- better discovery for JS-heavy targets

It still avoids active exploitation and does not blindly submit arbitrary workflows.

## Code Scanning

`code-scan` currently looks for:

- embedded secrets and password-like assignments
- hardcoded connection strings
- SQL query string concatenation
- debug mode
- weak hashes
- dangerous deserialization
- `eval(...)` / `exec(...)`
- `shell=True`
- `verify=False`
- Django `ALLOWED_HOSTS = ['*']`
- hardcoded Flask `SECRET_KEY`
- CSRF disabled
- unsafe upload save patterns
- path traversal sinks
- insecure temporary file creation
- dependency manifest risks in:
  - `requirements.txt`
  - `pyproject.toml`
  - `package.json`

Dependency findings currently include:

- unpinned or weakly pinned dependencies
- direct VCS or local-path dependencies
- package install hook scripts

## Database Scanning

`db-scan` is read-only and expects explicit user-supplied credentials.

Supported engines:

- PostgreSQL
- MySQL
- MSSQL

Current checks include things like:

- version inventory
- transport/encryption posture
- current login/user context
- privilege review
- risky DB settings
- sensitive-looking column names
- MSSQL-specific checks such as `xp_cmdshell`, `TRUSTWORTHY`, and guest `CONNECT`

Examples already validated during development:

- PostgreSQL local lab scan
- code-scan lab with intentionally insecure test files

## Reports

AccuScanner writes JSON and HTML reports, including timestamped output when requested.

Typical output:

```text
reports/20260420_120000/
  target-name-web-20260420_120000.json
  target-name-web-20260420_120000.html
```

HTML reports include:

- severity summary
- top risks
- grouped findings
- remediation guidance
- code findings grouped by category and file
- web attack-surface inventory where applicable

## Notes

- Web scanning is defensive and exposure-focused, not exploit-focused.
- Browser-assisted mode improves visibility, but it is not a full DAST engine.
- Code scanning is local-path based and does not clone repositories automatically.
- Database scanning is read-only and uses credentials you explicitly provide.
- Optional features require their extras to be installed.
- `nmap` is a required system dependency for network and web scan modes.

## Ethical Use

Use AccuScanner only on systems, applications, codebases, and databases you own or are explicitly authorized to assess.
