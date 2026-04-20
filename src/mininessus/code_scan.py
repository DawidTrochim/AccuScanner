from __future__ import annotations

import re
from collections.abc import Iterable
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
    (
        "CODE-EXEC-001",
        "Shell execution with shell=True detected",
        "high",
        "code_execution",
        re.compile(r"(?i)\b(?:subprocess\.(?:run|popen|call|check_call|check_output)|os\.system)\b[^\n]*\bshell\s*=\s*true"),
        "Avoid invoking shell commands with shell=True when input can be influenced externally; prefer argument lists and strict validation.",
        ["code", "execution", "shell"],
    ),
    (
        "CODE-EXEC-002",
        "Dynamic code execution detected",
        "high",
        "code_execution",
        re.compile(r"(?i)\b(?:eval|exec)\s*\("),
        "Avoid dynamic code execution on untrusted input and replace it with safer parsing or dispatch patterns.",
        ["code", "execution"],
    ),
    (
        "CODE-TLS-001",
        "TLS verification disabled in client request",
        "medium",
        "code_transport",
        re.compile(r"(?i)\b(?:requests\.(?:get|post|put|delete|request|session)|httpx\.(?:get|post|put|delete|request|client))\b[^\n]*\bverify\s*=\s*false"),
        "Keep certificate verification enabled in outbound requests unless you have a tightly controlled trust model and explicit certificate pinning.",
        ["code", "transport", "tls"],
    ),
    (
        "CODE-FRAMEWORK-001",
        "Wildcard Django ALLOWED_HOSTS detected",
        "medium",
        "code_framework",
        re.compile(r"(?i)\bALLOWED_HOSTS\b\s*=\s*\[[^\]]*['\"]\*['\"][^\]]*\]"),
        "Restrict Django ALLOWED_HOSTS to the specific hostnames or domains your application should serve.",
        ["code", "framework", "django"],
    ),
    (
        "CODE-FRAMEWORK-002",
        "Flask secret key hardcoded in source",
        "medium",
        "code_framework",
        re.compile(r"(?i)(?:app\.config\[['\"]SECRET_KEY['\"]\]\s*[:=]\s*['\"][^'\"]{8,}['\"]|\bSECRET_KEY\b\s*[:=]\s*['\"][^'\"]{8,}['\"])"),
        "Move Flask or general application secret keys into environment-backed secret management instead of embedding them in source.",
        ["code", "framework", "flask", "secrets"],
    ),
    (
        "CODE-FRAMEWORK-003",
        "CSRF protection explicitly disabled",
        "medium",
        "code_framework",
        re.compile(r"(?i)\b(?:WTF_CSRF_ENABLED|CSRF_ENABLED)\b\s*[:=]\s*(?:false|0|off)"),
        "Keep CSRF protection enabled for state-changing browser workflows unless the route is strictly non-browser and otherwise protected.",
        ["code", "framework", "csrf"],
    ),
    (
        "CODE-FILE-001",
        "Potential unsafe file upload save pattern",
        "high",
        "code_file_handling",
        re.compile(r"(?i)\b(?:file|upload|uploaded_file)\.save\s*\([^)\n]*(?:filename|request\.files|uploaded_file\.filename|file\.filename)"),
        "Validate upload destinations and sanitize filenames before saving user-controlled files.",
        ["code", "files", "upload"],
    ),
    (
        "CODE-FILE-002",
        "Potential path traversal sink with user-controlled path",
        "high",
        "code_file_handling",
        re.compile(r"(?i)\b(?:open|send_file|FileResponse|os\.path\.join)\s*\([^)\n]*(?:request\.(?:args|form|get_json)|user_(?:input|path)|filename)"),
        "Avoid passing user-controlled paths directly into file access APIs; normalize, validate, and constrain paths first.",
        ["code", "files", "path-traversal"],
    ),
    (
        "CODE-TEMP-001",
        "Insecure temporary file creation detected",
        "medium",
        "code_file_handling",
        re.compile(r"(?i)\btempfile\.mktemp\s*\("),
        "Use secure temporary file helpers such as NamedTemporaryFile or mkstemp instead of mktemp.",
        ["code", "files", "tempfile"],
    ),
]

DEPENDENCY_RULES = [
    (
        "CODE-DEPS-001",
        "Unpinned or weakly pinned dependency specification",
        "medium",
        "code_dependencies",
        "Dependency manifests include package versions that are not strictly pinned.",
        "Pin dependencies to reviewed versions where practical and use a dependency update process that includes security review.",
        ["code", "dependencies", "supply-chain"],
    ),
    (
        "CODE-DEPS-002",
        "Direct VCS or local path dependency detected",
        "medium",
        "code_dependencies",
        "A dependency manifest references a direct VCS URL or local editable/path dependency.",
        "Review whether direct VCS or local-path dependencies are necessary and ensure their provenance and update path are tightly controlled.",
        ["code", "dependencies", "supply-chain"],
    ),
    (
        "CODE-DEPS-003",
        "Package install hook script present",
        "low",
        "code_dependencies",
        "A Node package manifest declares install-time lifecycle scripts that deserve manual review.",
        "Review lifecycle scripts such as preinstall or install to make sure dependency installation does not execute unsafe commands.",
        ["code", "dependencies", "nodejs", "manual-review"],
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
        findings.extend(_scan_dependency_manifest(relative_path, content))

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


def _scan_dependency_manifest(relative_path: str, content: str) -> list[Finding]:
    manifest_name = Path(relative_path).name.lower()
    findings: list[Finding] = []
    if manifest_name == "requirements.txt":
        findings.extend(_scan_requirements_manifest(relative_path, content))
    elif manifest_name == "pyproject.toml":
        findings.extend(_scan_pyproject_manifest(relative_path, content))
    elif manifest_name == "package.json":
        findings.extend(_scan_package_json_manifest(relative_path, content))
    return findings


def _scan_requirements_manifest(relative_path: str, content: str) -> list[Finding]:
    findings: list[Finding] = []
    for line_number, raw_line in enumerate(content.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        normalized = line.lower()
        if normalized.startswith(("-e ", "--editable ")):
            findings.append(_dependency_finding("CODE-DEPS-002", relative_path, line_number, raw_line))
            continue
        if any(marker in normalized for marker in ("git+", "svn+", "hg+", "bzr+", "file://", " @ file:", " @ git+")):
            findings.append(_dependency_finding("CODE-DEPS-002", relative_path, line_number, raw_line))
            continue
        if "==" not in line and not line.startswith(("-r ", "--requirement ")):
            findings.append(_dependency_finding("CODE-DEPS-001", relative_path, line_number, raw_line))
    return findings


def _scan_pyproject_manifest(relative_path: str, content: str) -> list[Finding]:
    findings: list[Finding] = []
    in_dependencies_block = False
    for line_number, raw_line in enumerate(content.splitlines(), start=1):
        stripped = raw_line.strip()
        if not stripped:
            continue
        if stripped.startswith("["):
            in_dependencies_block = stripped in {
                "[project]",
                "[project.optional-dependencies]",
                "[tool.poetry.dependencies]",
                "[tool.poetry.group.dev.dependencies]",
            }
        if stripped.startswith("dependencies = ["):
            in_dependencies_block = True
            continue
        if not in_dependencies_block and not any(token in stripped for token in ("dependencies", "optional-dependencies", "tool.poetry.dependencies")):
            continue
        if not any(ch in stripped for ch in ('"', "'")):
            continue
        lowered = stripped.lower()
        if any(marker in lowered for marker in ("git+", "path =", "url =", "develop = true", "editable = true")):
            findings.append(_dependency_finding("CODE-DEPS-002", relative_path, line_number, raw_line))
            continue
        if _looks_like_unpinned_dependency_spec(stripped):
            findings.append(_dependency_finding("CODE-DEPS-001", relative_path, line_number, raw_line))
    return findings


def _scan_package_json_manifest(relative_path: str, content: str) -> list[Finding]:
    findings: list[Finding] = []
    current_section: str | None = None
    install_script_names = {"preinstall", "install", "postinstall", "prepare"}
    dependency_sections = {"dependencies", "devDependencies", "peerDependencies", "optionalDependencies"}
    for line_number, raw_line in enumerate(content.splitlines(), start=1):
        stripped = raw_line.strip()
        section_match = re.match(r'"([^"]+)"\s*:\s*\{', stripped)
        if section_match:
            current_section = section_match.group(1)
            continue
        if stripped.startswith("}"):
            current_section = None
            continue
        if current_section in dependency_sections:
            dep_match = re.match(r'"([^"]+)"\s*:\s*"([^"]+)"', stripped)
            if not dep_match:
                continue
            version = dep_match.group(2).strip()
            lowered = version.lower()
            if lowered.startswith(("git+", "github:", "file:", "link:", "workspace:", "http://", "https://")):
                findings.append(_dependency_finding("CODE-DEPS-002", relative_path, line_number, raw_line))
                continue
            if _looks_like_unpinned_dependency_spec(version):
                findings.append(_dependency_finding("CODE-DEPS-001", relative_path, line_number, raw_line))
        if current_section == "scripts":
            script_match = re.match(r'"([^"]+)"\s*:\s*"([^"]+)"', stripped)
            if script_match and script_match.group(1) in install_script_names:
                findings.append(_dependency_finding("CODE-DEPS-003", relative_path, line_number, raw_line))
    return findings


def _looks_like_unpinned_dependency_spec(spec: str) -> bool:
    cleaned = spec.strip().strip(",").strip('"').strip("'")
    lowered = cleaned.lower()
    if not cleaned:
        return False
    if any(marker in lowered for marker in ("git+", "file:", "path =", "url =", "workspace:", "link:", "github:")):
        return False
    if "==" in cleaned:
        return False
    if re.fullmatch(r"[A-Za-z0-9_.-]+\s*=\s*['\"][^'\"]+['\"]", cleaned):
        cleaned = cleaned.split("=", 1)[1].strip().strip('"').strip("'")
        lowered = cleaned.lower()
        if "==" in cleaned:
            return False
    weak_markers: Iterable[str] = ("^", "~", ">=", "<=", ">", "<", "!=", "*")
    return any(marker in cleaned for marker in weak_markers) or re.fullmatch(r"[A-Za-z0-9_.-]+", cleaned) is not None


def _dependency_finding(rule_id: str, relative_path: str, line_number: int, line: str) -> Finding:
    title, severity, category, description, recommendation, tags = next(
        (
            title,
            severity,
            category,
            description,
            recommendation,
            tags,
        )
        for finding_id, title, severity, category, description, recommendation, tags in DEPENDENCY_RULES
        if finding_id == rule_id
    )
    return build_finding(
        finding_id=f"{rule_id}-{relative_path}-{line_number}",
        title=title,
        severity=severity,
        category=category,
        target=relative_path,
        description=description,
        evidence=f"{relative_path}:{line_number}: {line.strip()[:240]}",
        recommendation=recommendation,
        confidence="medium",
        tags=tags,
    )


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
