"""Vulnerability-to-service matching engine.

Takes vulnerability records and the internal asset inventory to determine
which services are actually affected.  Handles:
  - Exact component name matching
  - Alias / fuzzy name normalization
  - Version range checking
  - Confidence scoring
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Literal

from app.models import Component, Service, ServiceComponent, Vulnerability

# Common aliases: canonical → set of alternate names
ALIASES: dict[str, set[str]] = {
    "spring-boot": {"springboot", "spring_boot", "org.springframework.boot"},
    "express": {"expressjs", "express.js"},
    "tensorflow": {"tf", "tensor-flow"},
    "bouncy-castle": {"bouncycastle", "bcprov", "org.bouncycastle"},
    "jsonwebtoken": {"jwt", "jose"},
    "pandas": {"pd"},
    "numpy": {"np"},
    "scikit-learn": {"sklearn", "scikit_learn"},
    "keycloak": {"keycloak-server", "keycloak-core"},
    "jpos": {"jpos-core", "org.jpos"},
}

# Reverse lookup
_REVERSE_ALIASES: dict[str, str] = {}
for canonical, alts in ALIASES.items():
    for alt in alts:
        _REVERSE_ALIASES[alt.lower()] = canonical
    _REVERSE_ALIASES[canonical.lower()] = canonical


def _normalize_name(name: str) -> str:
    """Normalize a package/component name to a canonical form."""
    lower = name.strip().lower()
    return _REVERSE_ALIASES.get(lower, lower)


def _parse_version(v: str) -> tuple[int, ...]:
    """Parse a version string into a tuple of ints for comparison."""
    parts = re.findall(r"\d+", v)
    return tuple(int(p) for p in parts) if parts else (0,)


def _version_matches_rule(current_version: str, rule: str) -> bool:
    """Check if *current_version* satisfies an affected-versions rule.

    Supports rules like:
      '<2.1.10'  → version < 2.1.10
      '>=3.0,<3.2.4'
      '*' → all versions
    """
    if not rule or rule.strip() == "*":
        return True
    current = _parse_version(current_version)
    for part in rule.split(","):
        part = part.strip()
        if part.startswith("<="):
            if not (current <= _parse_version(part[2:])):
                return False
        elif part.startswith("<"):
            if not (current < _parse_version(part[1:])):
                return False
        elif part.startswith(">="):
            if not (current >= _parse_version(part[2:])):
                return False
        elif part.startswith(">"):
            if not (current > _parse_version(part[1:])):
                return False
        elif part.startswith("=="):
            if current != _parse_version(part[2:]):
                return False
        elif part.startswith("!="):
            if current == _parse_version(part[2:]):
                return False
        else:
            # Treat bare version as exact match if no operator
            pass
    return True


@dataclass
class VulnMatch:
    """One matching record: a vulnerability affects a component in a service."""
    vulnerability_id: str
    cve_id: str
    component_name: str
    component_version: str
    service_name: str
    confidence: Literal["high", "medium", "low"]
    match_reason: str
    fixed_version: str
    currently_exposed: bool = True


@dataclass
class MatchingEngine:
    """Match vulnerabilities against the internal service/component inventory."""

    services: list[Service]
    components: list[Component] = field(default_factory=list)
    service_components: list[ServiceComponent] = field(default_factory=list)

    def _build_index(self) -> dict[str, list[tuple[Service, str, str]]]:
        """Build a normalized-name → [(service, component_name, version)] index.

        If rich component data is available, use it.  Otherwise fall back to
        the simple ``service.components`` string list (prototype mode).
        """
        idx: dict[str, list[tuple[Service, str, str]]] = {}
        svc_map = {s.name: s for s in self.services}

        if self.service_components and self.components:
            comp_map = {c.component_id: c for c in self.components}
            for sc in self.service_components:
                comp = comp_map.get(sc.component_id)
                svc = svc_map.get(sc.service_id)
                if comp and svc:
                    canon = _normalize_name(comp.name)
                    idx.setdefault(canon, []).append((svc, comp.name, comp.version))
        else:
            # Fall back to flat component name list on Service
            for svc in self.services:
                for comp_name in svc.components:
                    canon = _normalize_name(comp_name)
                    idx.setdefault(canon, []).append((svc, comp_name, "0.0.0"))
        return idx

    def match(self, vulnerabilities: list[Vulnerability]) -> list[VulnMatch]:
        """Run matching across all vulnerabilities and return matches."""
        index = self._build_index()
        matches: list[VulnMatch] = []

        for vuln in vulnerabilities:
            canon = _normalize_name(vuln.component)
            entries = index.get(canon, [])
            for svc, comp_name, version in entries:
                # Version rule check
                rule = getattr(vuln, "affected_versions_rule", None) or ""
                version_ok = _version_matches_rule(version, rule) if version != "0.0.0" else True

                if not version_ok:
                    continue

                # Confidence
                if comp_name.lower() == vuln.component.lower():
                    confidence: Literal["high", "medium", "low"] = "high"
                    reason = "Exact component name match"
                elif _normalize_name(comp_name) == canon:
                    confidence = "medium"
                    reason = f"Alias match ({comp_name} → {canon})"
                else:
                    confidence = "low"
                    reason = "Fuzzy match"

                if version != "0.0.0" and version_ok:
                    reason += f"; version {version} within affected range"
                    if confidence == "medium":
                        confidence = "high"

                matches.append(VulnMatch(
                    vulnerability_id=getattr(vuln, "vulnerability_id", vuln.cve_id),
                    cve_id=vuln.cve_id,
                    component_name=comp_name,
                    component_version=version,
                    service_name=svc.name,
                    confidence=confidence,
                    match_reason=reason,
                    fixed_version=vuln.patch_version,
                    currently_exposed=True,
                ))
        return matches
