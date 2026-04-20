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


def test_build_database_config_supports_mssql_defaults():
    config = build_database_config(
        db_type="mssql",
        host="sql.internal",
        database="appdb",
        user="audit",
        password="secret",
    )

    assert config.db_type == "mssql"
    assert config.host == "sql.internal"
    assert config.port == 1433
    assert config.target == "mssql://sql.internal:1433/appdb"


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


@patch("mininessus.db_scan._scan_mssql")
def test_scan_database_dispatches_to_mssql(mock_scan_mssql):
    mock_scan_mssql.return_value = (
        [
            Finding(
                id="DB-MSSQL-001",
                title="MSSQL server version inventory",
                severity="info",
                category="db_posture",
                target="mssql://sql.internal:1433/appdb",
                description="Inventory",
                evidence="Version: SQL Server 2022",
                recommendation="Patch regularly.",
            )
        ],
        [],
    )
    config = DatabaseConfig(
        db_type="mssql",
        host="sql.internal",
        port=1433,
        database="appdb",
        user="audit",
        password="secret",
    )

    target, findings, errors = scan_database(config)

    assert target == "mssql://sql.internal:1433/appdb"
    assert not errors
    assert findings[0].id == "DB-MSSQL-001"


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
        if "show password_encryption" in query:
            return ("md5",)
        if "show log_connections" in query:
            return ("off",)
        if "bool_or(privilege_type = 'usage')" in query or "aclexplode" in query:
            return (True, False)
        return None

    def fetchall(self):
        query = self.last_query.lower()
        if "information_schema.columns" in query:
            return [("public", "customers", "password_hash")]
        if "relrowsecurity = false" in query:
            return [("public", "customers")]
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
    assert {finding.id for finding in findings} >= {
        "DB-POSTGRES-001",
        "DB-POSTGRES-003",
        "DB-POSTGRES-004",
        "DB-POSTGRES-005",
        "DB-POSTGRES-006",
        "DB-POSTGRES-007",
        "DB-POSTGRES-008",
    }
    assert fake_connection.cursor_instance.closed is True
    assert fake_connection.closed is True


class _FakeMSSQLCursor:
    def __init__(self):
        self.last_query = ""
        self.closed = False

    def execute(self, query: str):
        self.last_query = query.strip()

    def fetchone(self):
        query = self.last_query.lower()
        if "select @@version" in query:
            return ("Microsoft SQL Server 2022",)
        if "original_login()" in query:
            return ("audit_user",)
        if "encrypt_option" in query:
            return ("FALSE",)
        if "is_srvrolemember('sysadmin')" in query:
            return (1,)
        if "xp_cmdshell" in query:
            return (1,)
        return None

    def fetchall(self):
        query = self.last_query.lower()
        if "information_schema.columns" in query:
            return [("dbo", "customers", "password_hash")]
        return []

    def close(self):
        self.closed = True


class _FakeMSSQLConnection:
    def __init__(self):
        self.cursor_instance = _FakeMSSQLCursor()
        self.closed = False

    def cursor(self):
        return self.cursor_instance

    def close(self):
        self.closed = True


def test_scan_database_supports_mssql_queries():
    fake_connection = _FakeMSSQLConnection()
    fake_pytds = types.ModuleType("pytds")
    fake_pytds.connect = lambda **_: fake_connection
    config = DatabaseConfig(
        db_type="mssql",
        host="127.0.0.1",
        port=1433,
        database="accuscanner_lab",
        user="audit_user",
        password="secret",
    )

    with patch.dict(sys.modules, {"pytds": fake_pytds}):
        target, findings, errors = scan_database(config)

    assert target == "mssql://127.0.0.1:1433/accuscanner_lab"
    assert not errors
    assert {finding.id for finding in findings} >= {
        "DB-MSSQL-001",
        "DB-MSSQL-002",
        "DB-MSSQL-003",
        "DB-MSSQL-004",
        "DB-MSSQL-005",
        "DB-MSSQL-006",
    }
    assert fake_connection.cursor_instance.closed is True
    assert fake_connection.closed is True
