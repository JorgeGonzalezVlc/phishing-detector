from pydantic import BaseModel
from typing import Optional


class EmailInput(BaseModel):
    """Lo que recibe la API — el ID del email de Gmail."""
    email_id: str


class IOCs(BaseModel):
    """Indicadores de compromiso extraídos del email."""
    urls:          list[str] = []
    ips:           list[str] = []
    domains:       list[str] = []
    sender_domain: str = ""
    emails:        list[str] = []


class RiskAnalysis(BaseModel):
    """Resultado del motor de reglas."""
    score:    int
    severity: str
    reasons:  list[str] = []


class AnalysisResponse(BaseModel):
    """Respuesta completa que devuelve la API."""
    email_id:              str
    subject:               str
    sender:                str
    classification:        str
    risk_score:            int
    severity:              str
    mitre_technique:       str
    mitre_technique_name:  str
    reasons:               list[str]
    attack_summary:        str
    recommended_action:    str
    iocs:                  IOCs