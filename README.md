# 🛡️ Phishing Detector

Sistema de detección inteligente de phishing por email mediante IA, desarrollado en Python.

## ¿Qué hace?

Analiza emails de Gmail en busca de indicadores de phishing combinando dos enfoques:

- **Motor de reglas** — detecta patrones conocidos: urgencia, spoofing, dominios sospechosos, TLDs maliciosos, petición de credenciales...
- **Análisis con IA** — Claude (Anthropic) actúa como analista SOC, identifica técnicas MITRE ATT&CK y genera un informe estructurado

## Ejemplo de output

```json
{
  "classification": "phishing",
  "risk_score": 100,
  "severity": "critical",
  "mitre_technique": "T1566.002",
  "mitre_technique_name": "Phishing: Spearphishing Link",
  "reasons": [
    "Dominio fraudulento suplantando al Banco Santander con TLD .tk",
    "Reply-To diferente al remitente — técnica clásica de spoofing",
    "Solicitud explícita de credenciales mediante enlace HTTP sin cifrado"
  ],
  "attack_summary": "Ataque de phishing bancario dirigido a clientes del Banco Santander. El atacante suplanta la identidad de la entidad mediante un dominio fraudulento para redirigir a las víctimas a una página de robo de credenciales.",
  "recommended_action": "escalate"
}
```

## Arquitectura

Gmail API → Parser → IOC Extractor → Risk Engine → LLM (Claude) → JSON Response (SQLite + FastAPI)

## Tecnologías

- **Python** — lenguaje principal
- **FastAPI** — API REST para exponer el servicio
- **Anthropic Claude** — análisis inteligente y clasificación
- **Gmail API** — lectura de emails
- **SQLAlchemy + SQLite** — persistencia de análisis
- **Pydantic** — validación de datos
- **tldextract, dnspython, BeautifulSoup** — extracción de IOCs

## IOCs detectados

- URLs y dominios maliciosos
- Direcciones IP en headers
- TLDs sospechosos (.tk, .xyz, .ml...)
- Extensiones de adjuntos peligrosas
- Spoofing de remitente (Reply-To vs From)
- Lenguaje urgente / ingeniería social
- Petición de credenciales

## Instalación

```bash
git clone https://github.com/JorgeGonzalezVlc/phishing-detector
cd phishing-detector
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

Configura tus credenciales en `.env` (ver `.env.example`).

## Roadmap

- [x] Motor de reglas y heurísticas
- [x] Extracción de IOCs
- [x] Análisis con LLM + MITRE ATT&CK
- [x] API REST con FastAPI
- [x] Persistencia en base de datos
- [ ] Conexión Gmail API
- [ ] Embeddings y RAG para correlación de campañas
- [ ] Dashboard de análisis
- [ ] Integración con VirusTotal

## Autor

Jorge González — [LinkedIn](https://www.linkedin.com/in/jorge-gonz%C3%A1lez-gonz%C3%A1lez-5740614b/)

