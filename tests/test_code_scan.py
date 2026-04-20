from pathlib import Path

from mininessus.code_scan import scan_codebase


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
