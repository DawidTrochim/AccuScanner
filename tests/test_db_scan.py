import sys
import types
from unittest.mock import patch

from mininessus.db_scan import DatabaseConfig, build_database_config, scan_database
from mininessus.models import Finding


def test_build_database_config_from_connection_string():
    config = build_database_config(
        db_type="postgres",
        connection_string="postgres://audit:secret@db.internal:5432/appdb",
    )

    assert config.db_type == "postgres"
    assert config.host == "db.internal"
    assert config.port == 5432
    assert config.database == "appdb"
    assert config.user == "audit"
    assert config.password == "secret"


@patch("mininessus.db_scan._scan_postgres")
def test_scan_database_dispatches_to_postgres(mock_scan_postgres):
    mock_scan_postgres.return_value = (
        [
            Finding(
                id="DB-POSTGRES-001",
                title="PostgreSQL server version inventory",
                severity="info",
                category="db_posture",
                target="postgres://db.internal:5432/appdb",
                description="Inventory",
                evidence="Version: 16",
                recommendation="Patch regularly.",
            )
        ],
        [],
    )
    config = DatabaseConfig(
        db_type="postgres",
        host="db.internal",
        port=5432,
        database="appdb",
        user="audit",
        password="secret",
    )

    target, findings, errors = scan_database(config)

    assert target == "postgres://db.internal:5432/appdb"
    assert not errors
    assert findings[0].id == "DB-POSTGRES-001"


class _FakeCursor:
    def __init__(self):
        self.executed: list[str] = []
        self.last_query = ""
        self.closed = False

    def execute(self, query: str):
        self.executed.append(query.strip())
        self.last_query = query.strip()

    def fetchone(self):
        query = self.last_query.lower()
        if "select version()" in query:
            return ("PostgreSQL 16.0",)
        if "show ssl" in query:
            return ("on",)
        if "select current_user" in query:
            return ("audit_user",)
        return None

    def fetchall(self):
        query = self.last_query.lower()
        if "role_schema_grants" in query:
            return []
        if "information_schema.columns" in query:
            return [("public", "customers", "password_hash")]
        return []

    def close(self):
        self.closed = True


class _FakeConnection:
    def __init__(self):
        self.cursor_instance = _FakeCursor()
        self.closed = False

    def cursor(self):
        return self.cursor_instance

    def close(self):
        self.closed = True


def test_scan_database_supports_pg8000_cursor_without_context_manager():
    fake_connection = _FakeConnection()
    fake_pg8000 = types.ModuleType("pg8000")
    fake_dbapi = types.ModuleType("pg8000.dbapi")
    fake_dbapi.connect = lambda **_: fake_connection
    fake_pg8000.dbapi = fake_dbapi
    config = DatabaseConfig(
        db_type="postgres",
        host="127.0.0.1",
        port=5432,
        database="accuscanner_lab",
        user="audit_user",
        password="secret",
    )

    with patch.dict(sys.modules, {"pg8000": fake_pg8000, "pg8000.dbapi": fake_dbapi}):
        target, findings, errors = scan_database(config)

    assert target == "postgres://127.0.0.1:5432/accuscanner_lab"
    assert not errors
    assert {finding.id for finding in findings} >= {"DB-POSTGRES-001", "DB-POSTGRES-003", "DB-POSTGRES-005"}
    assert fake_connection.cursor_instance.closed is True
    assert fake_connection.closed is True
