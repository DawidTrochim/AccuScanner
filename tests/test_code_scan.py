from pathlib import Path

from mininessus.code_scan import scan_codebase
from mininessus.interactive import _code_scan_args


def test_code_scan_finds_secrets_and_sql_patterns():
    root = Path("test-code-scan-fixture")
    root.mkdir(exist_ok=True)
    app_path = root / "app.py"
    settings_path = root / "settings.py"
    try:
        app_path.write_text(
            "AWS_KEY = 'AKIA1234567890ABCDEF'\n"
            "cursor.execute(f\"SELECT * FROM users WHERE id = {user_id}\")\n",
            encoding="utf-8",
        )
        settings_path.write_text("DEBUG = True\n", encoding="utf-8")

        target, findings, errors = scan_codebase(str(root))

        assert target.endswith("test-code-scan-fixture")
        assert not errors
        ids = {finding.id.split("-test-code-scan-fixture", 1)[0] if "-test-code-scan-fixture" in finding.id else finding.id.rsplit("-", 1)[0] for finding in findings}
        titles = {finding.title for finding in findings}
        assert "Potential AWS access key in source" in titles
        assert "Possible SQL query string concatenation" in titles
        assert "Debug mode enabled in code or config" in titles
    finally:
        app_path.unlink(missing_ok=True)
        settings_path.unlink(missing_ok=True)
        root.rmdir()


def test_code_scan_finds_sql_query_assignment_patterns():
    root = Path("test-code-scan-sql-assignment")
    app_path = root / "app.py"
    root.mkdir(exist_ok=True)
    try:
        app_path.write_text(
            'query = f"SELECT * FROM users WHERE id = {user_id}"\n',
            encoding="utf-8",
        )

        _target, findings, errors = scan_codebase(str(root), language="python")

        assert not errors
        assert any(finding.title == "Possible SQL query string concatenation" for finding in findings)
    finally:
        app_path.unlink(missing_ok=True)
        root.rmdir()


def test_code_scan_respects_excludes():
    root = Path("test-code-scan-exclude")
    root.mkdir(exist_ok=True)
    secret_path = root / "secret.env"
    try:
        secret_path.write_text("password='supersecret'\n", encoding="utf-8")
        _target, findings, _errors = scan_codebase(str(root), excludes=["secret.env"])
        assert findings == []
    finally:
        secret_path.unlink(missing_ok=True)
        root.rmdir()


def test_code_scan_ignores_own_regex_definition_and_help_examples():
    root = Path("test-code-scan-self-noise")
    root.mkdir(exist_ok=True)
    scanner_path = root / "code_scan.py"
    cli_path = root / "cli.py"
    try:
        scanner_path.write_text(
            're.compile(r"(?i)\\\\b(?:pickle\\\\.loads|yaml\\\\.load\\\\s*\\\\(|BinaryFormatter|unserialize\\\\s*\\\\()")\n',
            encoding="utf-8",
        )
        cli_path.write_text(
            'db_scan.add_argument("--connection-string", help="Connection string such as postgres://user:pass@host:5432/db")\n',
            encoding="utf-8",
        )

        _target, findings, errors = scan_codebase(str(root), language="python")

        assert not errors
        assert findings == []
    finally:
        scanner_path.unlink(missing_ok=True)
        cli_path.unlink(missing_ok=True)
        root.rmdir()


def test_interactive_code_scan_defaults_to_excluding_tests(monkeypatch):
    responses = iter(
        [
            ".",
            "",
            "y",
            "n",
            "",
            "",
            "",
            "",
        ]
    )
    monkeypatch.setattr("builtins.input", lambda _prompt="": next(responses))

    args = _code_scan_args()

    assert args[:2] == ["code-scan", "."]
    assert "--exclude" in args
    exclude_indexes = [index for index, value in enumerate(args) if value == "--exclude"]
    excludes = [args[index + 1] for index in exclude_indexes]
    assert "tests/" in excludes
