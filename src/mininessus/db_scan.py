from __future__ import annotations

from contextlib import closing
from dataclasses import dataclass
from urllib.parse import urlparse

from .models import Finding, build_finding


SENSITIVE_NAME_MARKERS = ("password", "secret", "token", "key", "ssn", "credit", "auth")


@dataclass(slots=True)
class DatabaseConfig:
    db_type: str
    host: str
    port: int
    database: str
    user: str
    password: str
    ssl_mode: str | None = None

    @property
    def target(self) -> str:
        return f"{self.db_type}://{self.host}:{self.port}/{self.database}"


def build_database_config(
    *,
    db_type: str,
    host: str | None = None,
    port: int | None = None,
    database: str | None = None,
    user: str | None = None,
    password: str | None = None,
    connection_string: str | None = None,
    ssl_mode: str | None = None,
) -> DatabaseConfig:
    if connection_string:
        parsed = urlparse(connection_string)
        inferred_db_type = parsed.scheme.lower()
        return DatabaseConfig(
            db_type=inferred_db_type,
            host=parsed.hostname or host or "localhost",
            port=parsed.port or port or default_port_for_db(inferred_db_type),
            database=(parsed.path or "/").lstrip("/") or database or "",
            user=parsed.username or user or "",
            password=parsed.password or password or "",
            ssl_mode=ssl_mode,
        )
    return DatabaseConfig(
        db_type=db_type.lower(),
        host=host or "localhost",
        port=port or default_port_for_db(db_type),
        database=database or "",
        user=user or "",
        password=password or "",
        ssl_mode=ssl_mode,
    )


def scan_database(config: DatabaseConfig) -> tuple[str, list[Finding], list[str]]:
    if config.db_type == "postgres":
        return config.target, *_scan_postgres(config)
    if config.db_type == "mysql":
        return config.target, *_scan_mysql(config)
    return config.target, [], [f"Unsupported database type: {config.db_type}"]


def default_port_for_db(db_type: str) -> int:
    return {"postgres": 5432, "mysql": 3306}.get(db_type.lower(), 0)


def _scan_postgres(config: DatabaseConfig) -> tuple[list[Finding], list[str]]:
    try:
        import pg8000.dbapi as pg_driver  # type: ignore[import-not-found]
    except ImportError:
        return [], ["PostgreSQL scanning requires optional dependency `pg8000`. Install it with `pip install -e \".[database]\"`."]

    findings: list[Finding] = []
    errors: list[str] = []
    try:
        connection = pg_driver.connect(
            host=config.host,
            port=config.port,
            database=config.database,
            user=config.user,
            password=config.password,
            timeout=5,
            ssl_context=True if config.ssl_mode else None,
        )
    except Exception as exc:
        return [], [f"PostgreSQL connection failed: {exc}"]

    try:
        with closing(connection.cursor()) as cursor:
            version = _safe_fetch_one_value(cursor, "SELECT version()")
            ssl_status = _safe_fetch_one_value(cursor, "SHOW ssl")
            current_user = _safe_fetch_one_value(cursor, "SELECT current_user")
            password_encryption = _safe_fetch_one_value(cursor, "SHOW password_encryption")
            log_connections = _safe_fetch_one_value(cursor, "SHOW log_connections")
            public_schema_privileges = _safe_fetch_one_row(
                cursor,
                """
                SELECT
                    BOOL_OR(privilege_type = 'USAGE') AS public_usage,
                    BOOL_OR(privilege_type = 'CREATE') AS public_create
                FROM pg_namespace
                CROSS JOIN LATERAL aclexplode(COALESCE(nspacl, acldefault('n', nspowner))) AS privileges
                WHERE nspname = 'public'
                  AND privileges.grantee = 0
                """,
            )
            sensitive_columns = _safe_fetch_all_rows(
                cursor,
                """
                SELECT table_schema, table_name, column_name
                FROM information_schema.columns
                WHERE table_schema NOT IN ('pg_catalog', 'information_schema')
                """,
            )
            sensitive_tables_without_rls = _safe_fetch_all_rows(
                cursor,
                """
                SELECT n.nspname, c.relname
                FROM pg_class c
                JOIN pg_namespace n ON n.oid = c.relnamespace
                WHERE c.relkind = 'r'
                  AND n.nspname NOT IN ('pg_catalog', 'information_schema')
                  AND c.relrowsecurity = false
                """,
            )
            if version:
                findings.append(
                    _db_finding(
                        "DB-POSTGRES-001",
                        "PostgreSQL server version inventory",
                        "info",
                        "db_posture",
                        config.target,
                        f"Detected PostgreSQL version information for the connected server.",
                        f"Version: {version}",
                        "Keep database versions current and align patching with supported release trains.",
                        ["database", "postgres"],
                    )
                )
            if str(ssl_status).lower() not in {"on", "true", "1"}:
                findings.append(
                    _db_finding(
                        "DB-POSTGRES-002",
                        "PostgreSQL SSL appears disabled",
                        "medium",
                        "db_transport",
                        config.target,
                        "The server reported that SSL is disabled or unavailable.",
                        f"SHOW ssl => {ssl_status}",
                        "Enable TLS for database connections and require encrypted transport where possible.",
                        ["database", "postgres", "transport"],
                    )
                )
            if str(password_encryption).lower() == "md5":
                findings.append(
                    _db_finding(
                        "DB-POSTGRES-006",
                        "PostgreSQL password encryption uses MD5",
                        "medium",
                        "db_auth",
                        config.target,
                        "The server is configured to hash passwords with MD5 instead of SCRAM-SHA-256.",
                        f"password_encryption => {password_encryption}",
                        "Prefer SCRAM-SHA-256 for PostgreSQL password hashing and rotate any credentials still stored with weaker schemes.",
                        ["database", "postgres", "auth"],
                    )
                )
            if current_user:
                findings.append(
                    _db_finding(
                        "DB-POSTGRES-003",
                        "Database login context captured",
                        "info",
                        "db_auth",
                        config.target,
                        "The scanner confirmed the active database user for the audit session.",
                        f"Current user: {current_user}",
                        "Use a dedicated low-privilege read-only audit role for posture scans.",
                        ["database", "postgres", "auth"],
                    )
                )
            if str(log_connections).lower() in {"off", "false", "0"}:
                findings.append(
                    _db_finding(
                        "DB-POSTGRES-007",
                        "PostgreSQL connection logging disabled",
                        "low",
                        "db_posture",
                        config.target,
                        "The server does not appear to log client connections.",
                        f"log_connections => {log_connections}",
                        "Enable connection logging where appropriate so authentication and access events are easier to audit.",
                        ["database", "postgres", "logging"],
                    )
                )
            public_usage = bool(public_schema_privileges[0]) if public_schema_privileges else False
            public_create = bool(public_schema_privileges[1]) if public_schema_privileges and len(public_schema_privileges) > 1 else False
            if public_usage or public_create:
                detected_privileges = []
                if public_usage:
                    detected_privileges.append("USAGE")
                if public_create:
                    detected_privileges.append("CREATE")
                findings.append(
                    _db_finding(
                        "DB-POSTGRES-004",
                        "PUBLIC privileges detected on PostgreSQL public schema",
                        "medium",
                        "db_privileges",
                        config.target,
                        "The PUBLIC role retains access on the default public schema.",
                        f"Privileges: {', '.join(detected_privileges)}",
                        "Review default schema grants and revoke unnecessary PUBLIC access.",
                        ["database", "postgres", "privileges"],
                    )
                )
            findings.extend(_sensitive_name_findings(config.target, sensitive_columns, "postgres"))
            findings.extend(_rls_review_findings(config.target, sensitive_columns, sensitive_tables_without_rls, "postgres"))
    except Exception as exc:
        errors.append(f"PostgreSQL inspection failed: {exc}")
    finally:
        try:
            connection.close()
        except Exception:
            pass

    return findings, errors


def _scan_mysql(config: DatabaseConfig) -> tuple[list[Finding], list[str]]:
    try:
        import pymysql  # type: ignore[import-not-found]
    except ImportError:
        return [], ["MySQL scanning requires optional dependency `PyMySQL`. Install it with `pip install -e \".[database]\"`."]

    findings: list[Finding] = []
    errors: list[str] = []
    try:
        connection = pymysql.connect(
            host=config.host,
            port=config.port,
            database=config.database,
            user=config.user,
            password=config.password,
            connect_timeout=5,
            ssl={"ssl": {}} if config.ssl_mode else None,
            read_timeout=5,
            write_timeout=5,
        )
    except Exception as exc:
        return [], [f"MySQL connection failed: {exc}"]

    try:
        with closing(connection.cursor()) as cursor:
            version = _safe_fetch_one_value(cursor, "SELECT VERSION()")
            current_user = _safe_fetch_one_value(cursor, "SELECT CURRENT_USER()")
            require_secure_transport = _safe_fetch_one_value(cursor, "SHOW VARIABLES LIKE 'require_secure_transport'", value_column=1)
            current_grants = _safe_fetch_all_rows(cursor, "SHOW GRANTS FOR CURRENT_USER()")
            local_infile = _safe_fetch_one_value(cursor, "SHOW VARIABLES LIKE 'local_infile'", value_column=1)
            sensitive_columns = _safe_fetch_all_rows(
                cursor,
                """
                SELECT table_schema, table_name, column_name
                FROM information_schema.columns
                WHERE table_schema NOT IN ('information_schema', 'mysql', 'performance_schema', 'sys')
                """,
            )
            if version:
                findings.append(
                    _db_finding(
                        "DB-MYSQL-001",
                        "MySQL server version inventory",
                        "info",
                        "db_posture",
                        config.target,
                        "Detected MySQL version information for the connected server.",
                        f"Version: {version}",
                        "Keep database versions current and align patching with supported release trains.",
                        ["database", "mysql"],
                    )
                )
            if str(require_secure_transport).lower() not in {"on", "1", "yes"}:
                findings.append(
                    _db_finding(
                        "DB-MYSQL-002",
                        "MySQL secure transport not enforced",
                        "medium",
                        "db_transport",
                        config.target,
                        "The server does not appear to require secure transport for client connections.",
                        f"require_secure_transport => {require_secure_transport}",
                        "Require TLS for database connections and disable unencrypted transport where possible.",
                        ["database", "mysql", "transport"],
                    )
                )
            if str(local_infile).lower() in {"on", "1", "yes"}:
                findings.append(
                    _db_finding(
                        "DB-MYSQL-006",
                        "MySQL LOCAL INFILE enabled",
                        "medium",
                        "db_posture",
                        config.target,
                        "The server reports that LOCAL INFILE is enabled for client file loading.",
                        f"local_infile => {local_infile}",
                        "Disable LOCAL INFILE unless it is operationally required and tightly controlled.",
                        ["database", "mysql", "posture"],
                    )
                )
            if current_user:
                findings.append(
                    _db_finding(
                        "DB-MYSQL-003",
                        "Database login context captured",
                        "info",
                        "db_auth",
                        config.target,
                        "The scanner confirmed the active database user for the audit session.",
                        f"Current user: {current_user}",
                        "Use a dedicated low-privilege read-only audit account for posture scans.",
                        ["database", "mysql", "auth"],
                    )
                )
            if any("ALL PRIVILEGES" in (row[0] or "").upper() for row in current_grants if row):
                findings.append(
                    _db_finding(
                        "DB-MYSQL-004",
                        "Broad MySQL grants detected for audit account",
                        "medium",
                        "db_privileges",
                        config.target,
                        "The supplied MySQL account appears to hold broad privileges.",
                        f"Grants: {' | '.join(row[0] for row in current_grants if row and row[0])}",
                        "Review whether the scan account can be reduced to a narrower read-only privilege set.",
                        ["database", "mysql", "privileges"],
                    )
                )
            findings.extend(_sensitive_name_findings(config.target, sensitive_columns, "mysql"))
    except Exception as exc:
        errors.append(f"MySQL inspection failed: {exc}")
    finally:
        try:
            connection.close()
        except Exception:
            pass

    return findings, errors


def _fetch_one_value(cursor, query: str, value_column: int = 0):
    cursor.execute(query)
    row = cursor.fetchone()
    if not row:
        return None
    return row[value_column] if isinstance(row, (list, tuple)) else row


def _fetch_all_rows(cursor, query: str):
    cursor.execute(query)
    return list(cursor.fetchall() or [])


def _fetch_one_row(cursor, query: str):
    cursor.execute(query)
    row = cursor.fetchone()
    if not row:
        return None
    return tuple(row) if isinstance(row, (list, tuple)) else (row,)


def _safe_fetch_one_value(cursor, query: str, value_column: int = 0):
    try:
        return _fetch_one_value(cursor, query, value_column=value_column)
    except Exception:
        return None


def _safe_fetch_all_rows(cursor, query: str):
    try:
        return _fetch_all_rows(cursor, query)
    except Exception:
        return []


def _safe_fetch_one_row(cursor, query: str):
    try:
        return _fetch_one_row(cursor, query)
    except Exception:
        return None


def _sensitive_name_findings(target: str, rows: list[tuple], db_type: str) -> list[Finding]:
    findings: list[Finding] = []
    matches: list[str] = []
    for row in rows:
        if len(row) < 3:
            continue
        schema_name, table_name, column_name = row[0], row[1], row[2]
        lowered = f"{schema_name}.{table_name}.{column_name}".lower()
        if any(marker in lowered for marker in SENSITIVE_NAME_MARKERS):
            matches.append(f"{schema_name}.{table_name}.{column_name}")
    if matches:
        findings.append(
            _db_finding(
                f"DB-{db_type.upper()}-005",
                f"Sensitive-looking column names detected in {db_type}",
                "low",
                "db_schema",
                target,
                "Schema metadata contains column names that likely store authentication or sensitive data.",
                f"Examples: {', '.join(matches[:10])}",
                "Review whether sensitive data is appropriately encrypted, access-controlled, and audited.",
                ["database", db_type, "schema", "manual-review"],
            )
        )
    return findings


def _rls_review_findings(target: str, sensitive_columns: list[tuple], row_security_rows: list[tuple], db_type: str) -> list[Finding]:
    if db_type != "postgres":
        return []
    sensitive_table_names = {
        f"{row[0]}.{row[1]}".lower()
        for row in sensitive_columns
        if len(row) >= 3 and any(marker in f"{row[0]}.{row[1]}.{row[2]}".lower() for marker in SENSITIVE_NAME_MARKERS)
    }
    tables_without_rls = {
        f"{row[0]}.{row[1]}".lower()
        for row in row_security_rows
        if len(row) >= 2
    }
    impacted = sorted(sensitive_table_names & tables_without_rls)
    if not impacted:
        return []
    return [
        _db_finding(
            "DB-POSTGRES-008",
            "Sensitive-looking PostgreSQL tables do not use row-level security",
            "low",
            "db_schema",
            target,
            "Tables with sensitive-looking columns were found without PostgreSQL row-level security enabled.",
            f"Examples: {', '.join(impacted[:10])}",
            "Review whether row-level security is appropriate for sensitive multi-tenant or user-scoped data tables.",
            ["database", "postgres", "schema", "manual-review"],
        )
    ]


def _db_finding(
    finding_id: str,
    title: str,
    severity: str,
    category: str,
    target: str,
    description: str,
    evidence: str,
    recommendation: str,
    tags: list[str],
) -> Finding:
    return build_finding(
        finding_id=finding_id,
        title=title,
        severity=severity,
        category=category,
        target=target,
        description=description,
        evidence=evidence,
        recommendation=recommendation,
        confidence="medium",
        tags=tags,
    )
