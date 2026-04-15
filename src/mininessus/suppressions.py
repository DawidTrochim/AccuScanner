from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from .models import Finding

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None


@dataclass(slots=True)
class SuppressionRule:
    ids: set[str]
    targets: set[str]
    severities: set[str]
    tags: set[str]
    until: str | None = None
    reason: str | None = None


def load_suppression_rules(path: str | None) -> list[SuppressionRule]:
    if not path:
        return []
    raw_text = Path(path).read_text(encoding="utf-8")
    if path.endswith(".json"):
        content = json.loads(raw_text)
    elif yaml is not None:
        content = yaml.safe_load(raw_text) or {}
    else:
        content = {"rules": []}
    return [_parse_rule(rule) for rule in content.get("rules", [])]


def apply_suppressions(findings: list[Finding], rules: list[SuppressionRule]) -> list[Finding]:
    if not rules:
        return findings
    return [finding for finding in findings if not any(_matches_rule(finding, rule) for rule in rules)]


def _parse_rule(raw_rule: dict) -> SuppressionRule:
    return SuppressionRule(
        ids={str(value) for value in raw_rule.get("ids", [])},
        targets={str(value) for value in raw_rule.get("targets", [])},
        severities={str(value).lower() for value in raw_rule.get("severities", [])},
        tags={str(value).lower() for value in raw_rule.get("tags", [])},
        until=raw_rule.get("until"),
        reason=raw_rule.get("reason"),
    )


def _matches_rule(finding: Finding, rule: SuppressionRule) -> bool:
    if rule.until and not _rule_is_active(rule.until):
        return False
    if rule.ids and finding.id not in rule.ids:
        return False
    if rule.targets and finding.target not in rule.targets:
        return False
    if rule.severities and finding.severity.lower() not in rule.severities:
        return False
    if rule.tags and not ({tag.lower() for tag in finding.tags} & rule.tags):
        return False
    return any((rule.ids, rule.targets, rule.severities, rule.tags))


def _rule_is_active(until: str) -> bool:
    try:
        expires = datetime.fromisoformat(until.replace("Z", "+00:00"))
    except ValueError:
        return True
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=UTC)
    return expires >= datetime.now(UTC)
