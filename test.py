from core.parser import parse_email
from core.ioc_extractor import extract_iocs
from core.risk_engine import calculate_risk_score
from core.llm_analyzer import analyze_with_llm
import json

# Email falso simulando un phishing típico de banco
raw_email_fake = {
    "id": "test_001",
    "payload": {
        "headers": [
            {"name": "From",     "value": "seguridad@santander-secure.tk"},
            {"name": "Reply-To", "value": "respuesta@gmail-fake.xyz"},
            {"name": "Subject",  "value": "URGENTE: Su cuenta ha sido suspendida"},
            {"name": "Date",     "value": "2025-05-16"},
            {"name": "Received", "value": "from 192.168.1.105"},
        ],
        "mimeType": "text/plain",
        "body": {
            "data": None
        }
    }
}

# Cuerpo del email falso en texto plano
body_fake = """
Estimado cliente,

Hemos detectado actividad sospechosa en su cuenta bancaria.
Su cuenta será suspendida en 24 horas si no verifica sus credenciales.

Por favor introduzca su usuario y contraseña en el siguiente enlace:
http://santander-secure.tk/verificar-cuenta

Si no actúa ahora perderá el acceso a su banca online.

Departamento de Seguridad
Banco Santander
"""

# Simulamos el parsed_email directamente
parsed = {
    "id":       "test_001",
    "subject":  "URGENTE: Su cuenta ha sido suspendida",
    "sender":   "seguridad@santander-secure.tk",
    "reply_to": "respuesta@gmail-fake.xyz",
    "date":     "2025-05-16",
    "headers":  raw_email_fake["payload"]["headers"],
    "body":     body_fake,
    "html":     ""
}

print("🔍 Ejecutando pipeline...\n")

# Paso 1 — IOCs
print("📌 Extrayendo IOCs...")
iocs = extract_iocs(parsed)
print(json.dumps(iocs, indent=2))

# Paso 2 — Risk Score
print("\n⚠️  Calculando risk score...")
risk = calculate_risk_score(parsed, iocs)
print(json.dumps(risk, indent=2))

# Paso 3 — LLM
print("\n🤖 Analizando con Claude...")
result = analyze_with_llm(parsed, iocs, risk)
print(json.dumps(result, indent=2, ensure_ascii=False))