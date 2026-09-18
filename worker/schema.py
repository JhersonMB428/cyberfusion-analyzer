"""Esquema normalizado de hallazgos.

Toda herramienta (nuclei, wpscan, o nuestros runners en Python) debe
convertir su salida nativa a esta forma. El resto del sistema NUNCA
ve el formato original de una herramienta.
"""
from dataclasses import dataclass, field, asdict
from typing import Any, Literal

Severity = Literal["info", "low", "medium", "high", "critical"]
Confidence = Literal["tentative", "firm", "confirmed"]
Effort = Literal["low", "medium", "high"]
Layer = Literal["surface", "cms", "app", "infra", "compliance"]

# Peso de cada severidad y TOPE maximo por severidad.
# El tope evita que veinte hallazgos leves hundan la nota como un critico.
WEIGHTS: dict[str, float] = {
    "critical": 35,
    "high": 15,
    "medium": 5,
    "low": 1.5,
    "info": 0,
}
CAPS: dict[str, float] = {
    "critical": 100,
    "high": 45,
    "medium": 20,
    "low": 10,
    "info": 0,
}


@dataclass
class Finding:
    finding_key: str          # id estable: "tls.cert.expiring_soon"
    layer: Layer
    source: str               # que runner lo produjo
    severity: Severity
    confidence: Confidence = "firm"
    effort: Effort = "medium"
    cve: list[str] = field(default_factory=list)
    cvss: float | None = None
    evidence: dict[str, Any] = field(default_factory=dict)
    status: str = "open"

    @property
    def title_key(self) -> str:
        return f"findings.{self.finding_key}.title"

    @property
    def remediation_key(self) -> str:
        return f"findings.{self.finding_key}.fix"

    def to_dict(self) -> dict:
        d = asdict(self)
        d["title_key"] = self.title_key
        d["remediation_key"] = self.remediation_key
        return d


def score(findings: list["Finding"]) -> int:
    """Puntuacion 0-100 con topes por severidad.

    Regla de negocio: sin criticos ni altos, nunca bajar de 65 (nota C).
    Reservamos D y F para sitios que de verdad estan en peligro.
    """
    penalty = 0.0
    for sev, weight in WEIGHTS.items():
        n = sum(1 for f in findings if f.severity == sev)
        penalty += min(n * weight, CAPS[sev])

    value = max(0, round(100 - penalty))

    worst = {f.severity for f in findings}
    if not (worst & {"critical", "high"}):
        value = max(value, 65)
    return value


def grade(value: int) -> str:
    for threshold, letter in ((90, "A"), (80, "B"), (65, "C"), (50, "D")):
        if value >= threshold:
            return letter
    return "F"
