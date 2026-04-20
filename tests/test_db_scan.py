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
