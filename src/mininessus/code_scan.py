from __future__ import annotations

import re
from pathlib import Path

from .models import Finding, build_finding


DEFAULT_EXCLUDED_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "__pycache__",
    "node_modules",
    "vendor",
    "dist",
    "build",
    ".next",
    ".pytest_cache",
}
TEXT_FILE_EXTENSIONS = {
    ".py",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".php",
    ".rb",
    ".java",
    ".cs",
    ".go",
    ".rs",
    ".env",
    ".json",
    ".yaml",
    ".yml",
    ".ini",
    ".cfg",
    ".conf",
    ".xml",
    ".sql",
    ".txt",
    ".md",
    ".properties",
}
LANGUAGE_EXTENSION_MAP = {
    "python": {".py"},
    "javascript": {".js", ".jsx"},
    "typescript": {".ts", ".tsx"},
    "php": {".php"},
    "csharp": {".cs"},
    "java": {".java"},
    "go": {".go"},
    "ruby": {".rb"},
    "rust": {".rs"},
    "config": {".env", ".json", ".yaml", ".yml", ".ini", ".cfg", ".conf", ".xml", ".properties"},
}

SECRET_RULES = [
    (
        "CODE-SECRET-001",
        "Potential AWS access key in source",
        "high",
        "code_secrets",
        re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        "Remove embedded cloud credentials from source files and move them into a secure secret store.",
        ["code", "secrets", "cloud"],
    ),
    (
        "CODE-SECRET-002",
        "Private key material in source",
        "critical",
        "code_secrets",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
        "Remove private keys from the repository immediately and rotate any credentials that may be exposed.",
        ["code", "secrets", "keys"],
    ),
    (
        "CODE-SECRET-003",
        "Hardcoded connection string detected",
        "high",
        "code_secrets",
        re.compile(r"\b(?:postgres(?:ql)?|mysql|mssql|mongodb)://[^\s\"']+"),
        "Move database connection strings into environment-specific secret management and avoid embedding credentials in code.",
        ["code", "secrets", "database"],
    ),
    (
        "CODE-SECRET-004",
        "Hardcoded password-like assignment",
        "medium",
        "code_secrets",
        re.compile(r"(?i)\b(?:password|passwd|pwd|secret|api[_-]?key)\b\s*[:=]\s*[\"'][^\"']{4,}[\"']"),
        "Replace hardcoded credentials or secret-like values with environment variables or a managed secret store.",
        ["code", "secrets"],
    ),
]
PATTERN_RULES = [
    (
        "CODE-INJECT-001",
        "Possible SQL query string concatenation",
        "high",
        "code_injection",
        re.compile(
            r"(?i)(?:"
            r"\b(?:execute|query|cursor\.execute|mysql_query|pg_query)\s*\([^)\n]*(?:select|insert|update|delete)[^)\n]*(?:\+|%s|\{.+\}|format\()"
            r"|"
            r"\b(?:query|sql|statement|stmt|command)\w*\s*=\s*(?:f[\"']|[\"']).*(?:select|insert|update|delete).*(?:\{.+\}|\+|%s|format\()"
            r")"
        ),
        "Use parameterized queries or prepared statements instead of building SQL queries through string concatenation or interpolation.",
        ["code", "injection", "sql"],
    ),
    (
        "CODE-CONFIG-001",
        "Debug mode enabled in code or config",
        "medium",
        "code_config",
        re.compile(r"(?im)\b(?:debug|app\.debug|display_errors)\b\s*[:=]\s*(?:true|1|on)"),
        "Disable debug mode in production-facing code and configuration.",
        ["code", "config"],
    ),
    (
        "CODE-CRYPTO-001",
        "Weak hash function usage detected",
        "medium",
        "code_crypto",
        re.compile(r"(?i)\b(?:md5|sha1)\s*\("),
        "Replace weak hashes such as MD5 and SHA1 with modern, context-appropriate cryptographic primitives.",
        ["code", "crypto"],
    ),
    (
        "CODE-DESERIAL-001",
        "Dangerous deserialization pattern detected",
        "high",
        "code_deserialization",
        re.compile(r"(?i)\b(?:pickle\.loads|yaml\.load\s*\(|BinaryFormatter|unserialize\s*\()"),
        "Review deserialization of untrusted input and switch to safer parsing patterns where possible.",
        ["code", "deserialization"],
    ),
]


def scan_codebase(
    path: str,
    *,
    excludes: list[str] | None = None,
    includes: list[str] | None = None,
    max_file_size_kb: int = 256,
    language: str | None = None,
) -> tuple[str, list[Finding], list[str]]:
    root = Path(path).expanduser().resolve()
    errors: list[str] = []
    findings: list[Finding] = []
    if not root.exists():
        return str(root), [], [f"Source path does not exist: {root}"]
    if not root.is_dir():
        return str(root), [], [f"Source path is not a directory: {root}"]

    include_patterns = [value.strip() for value in includes or [] if value.strip()]
    exclude_patterns = [value.strip() for value in excludes or [] if value.strip()]
    allowed_extensions = LANGUAGE_EXTENSION_MAP.get((language or "").lower())
    max_bytes = max_file_size_kb * 1024

    for file_path in root.rglob("*"):
        if not file_path.is_file():
            continue
        if any(part in DEFAULT_EXCLUDED_DIRS for part in file_path.parts):
            continue
        relative_path = file_path.relative_to(root).as_posix()
        if include_patterns and not any(pattern in relative_path for pattern in include_patterns):
            continue
        if exclude_patterns and any(pattern in relative_path for pattern in exclude_patterns):
            continue
        if allowed_extensions is not None and file_path.suffix.lower() not in allowed_extensions:
            continue
        if allowed_extensions is None and file_path.suffix.lower() not in TEXT_FILE_EXTENSIONS and not _looks_like_env_or_config(file_path.name):
            continue
        try:
            if file_path.stat().st_size > max_bytes:
                continue
            content = file_path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            errors.append(f"Failed to read {file_path}: {exc}")
            continue
        findings.extend(_scan_file_content(relative_path, content))

    return str(root), findings, errors


def _scan_file_content(relative_path: str, content: str) -> list[Finding]:
    findings: list[Finding] = []
    for line_number, line in enumerate(content.splitlines(), start=1):
        for finding_id, title, severity, category, pattern, recommendation, tags in SECRET_RULES:
            match = pattern.search(line)
            if not match:
                continue
            if _should_suppress_match(relative_path, line, finding_id):
                continue
            findings.append(
                build_finding(
                    finding_id=f"{finding_id}-{relative_path}-{line_number}",
                    title=title,
                    severity=severity,
                    category=category,
                    target=relative_path,
                    description="A potential secret or credential-like value was detected in source code or configuration.",
                    evidence=f"{relative_path}:{line_number}: {line.strip()[:240]}",
                    recommendation=recommendation,
                    confidence="medium",
                    tags=tags,
                )
            )
        for finding_id, title, severity, category, pattern, recommendation, tags in PATTERN_RULES:
            match = pattern.search(line)
            if not match:
                continue
            if _should_suppress_match(relative_path, line, finding_id):
                continue
            findings.append(
                build_finding(
                    finding_id=f"{finding_id}-{relative_path}-{line_number}",
                    title=title,
                    severity=severity,
                    category=category,
                    target=relative_path,
                    description="A source pattern associated with insecure implementation or configuration was detected.",
                    evidence=f"{relative_path}:{line_number}: {line.strip()[:240]}",
                    recommendation=recommendation,
                    confidence="medium",
                    tags=tags,
                )
            )
    return findings


def _should_suppress_match(relative_path: str, line: str, finding_id: str) -> bool:
    stripped = line.strip()
    lowered = stripped.lower()

    # Avoid self-referential hits where the scanner's own regex definitions
    # contain the patterns it is meant to detect.
    if relative_path.endswith("code_scan.py") and "re.compile(" in stripped:
        return True

    # Avoid instructional/example connection strings in CLI help text.
    if finding_id == "CODE-SECRET-003":
        if "help=" in lowered or "example" in lowered or "such as" in lowered:
            return True
        if any(sample in lowered for sample in ("postgres://user:pass@", "mysql://user:pass@", "mongodb://user:pass@", "mssql://user:pass@")):
            return True

    return False


def _looks_like_env_or_config(filename: str) -> bool:
    lowered = filename.lower()
    return lowered in {".env", "docker-compose.yml", "docker-compose.yaml"} or lowered.endswith((".env", ".config"))
