import re


# Palabras que indican urgencia o manipulación
URGENT_WORDS = [
    "urgente", "inmediatamente", "acción requerida", "actúe ahora", "actua ahora",
    "último aviso", "ultimo aviso", "su cuenta será suspendida", "cuenta suspendida",
    "cuenta bloqueada", "acceso bloqueado", "verifique ahora", "verificación requerida",
    "confirmar identidad", "actualice sus datos", "actividad sospechosa",
    "inicio de sesión sospechoso", "pago rechazado", "problema de facturación",
    "seguridad comprometida", "caduca hoy", "expira hoy", "riesgo de cierre",
    "evite la suspensión", "evite el bloqueo", "su cuenta ha sido limitada",
    "urgent", "immediately", "action required", "act now", "final warning",
    "last chance", "account suspended", "account blocked", "verify now",
    "verification required", "confirm your identity", "update your information",
    "suspicious activity", "unusual login attempt", "payment declined",
    "billing issue", "security alert", "expires today", "account limited",
    "avoid suspension", "avoid account closure", "your account has been compromised"
]

CREDENTIAL_WORDS = [
    "contraseña", "usuario", "credenciales", "iniciar sesión", "inicio de sesión",
    "pin", "tarjeta", "número de tarjeta", "cvv", "código de seguridad",
    "banca online", "token", "clave", "clave de acceso", "dni",
    "verificación bancaria", "datos personales", "validar identidad",
    "password", "username", "credentials", "login", "sign in",
    "card number", "credit card", "security code", "bank account",
    "banking verification", "access code", "authentication",
    "verify account", "personal information", "social security number", "ssn"
]

SCAM_WORDS = [
    "ha ganado", "premio", "sorteo", "reclame ahora", "oferta exclusiva",
    "regalo", "bonificación", "transferencia pendiente", "herencia",
    "inversión urgente", "inversión garantizada", "retorno asegurado",
    "duplica tu dinero", "you won", "winner", "claim now", "exclusive offer",
    "free gift", "bonus", "wire transfer", "inheritance", "urgent investment",
    "guaranteed investment", "double your money", "crypto opportunity"
]

DANGEROUS_EXTENSIONS = [
    ".exe", ".scr", ".bat", ".cmd", ".js", ".vbs", ".iso",
    ".zip", ".rar", ".7z", ".html", ".htm", ".ps1", ".lnk",
    ".docm", ".xlsm", ".hta"
]

LEGITIMATE_DOMAINS = [
    "google.com", "gmail.com", "microsoft.com", "office.com",
    "outlook.com", "live.com", "apple.com", "icloud.com",
    "amazon.com", "amazon.es", "paypal.com", "bankinter.com",
    "santander.com", "bbva.com", "caixabank.es", "ing.es",
    "openbank.es", "abanca.com", "sabadell.com", "netflix.com",
    "linkedin.com", "dropbox.com", "adobe.com", "docusign.net",
    "hacienda.gob.es", "agenciatributaria.es", "seg-social.es",
    "correos.es", "dgt.es"
]

SUSPICIOUS_TLDS = [
    ".ru", ".cn", ".tk", ".xyz", ".top", ".gq", ".ml",
    ".work", ".click", ".cf", ".ga", ".link", ".date",
    ".download", ".zip", ".mov"
]

def check_urgent_language(body: str) -> tuple:
    """Detecta lenguaje urgente en el cuerpo del email."""
    body_lower = body.lower()
    found = [word for word in URGENT_WORDS if word in body_lower]
    triggered = len(found) > 0
    return triggered, found


def check_credential_request(body: str) -> tuple:
    """Detecta petición de credenciales."""
    body_lower = body.lower()
    found = [word for word in CREDENTIAL_WORDS if word in body_lower]
    triggered = len(found) > 0
    return triggered, found


def check_spoofed_sender(sender: str, reply_to: str) -> bool:
    """
    Detecta spoofing básico — cuando el Reply-To es diferente al sender.
    Es una técnica común en phishing.
    """
    if not reply_to:
        return False
    
    sender_domain = sender.split("@")[-1].replace(">", "").strip()
    reply_domain = reply_to.split("@")[-1].replace(">", "").strip()
    
    return sender_domain != reply_domain


def check_suspicious_domains(domains: list) -> list:
    """Detecta dominios sospechosos que imitan dominios legítimos."""
    suspicious = []
    for domain in domains:
        for legit in LEGITIMATE_DOMAINS:
            legit_name = legit.split(".")[0]
            if legit_name in domain and domain != legit:
                suspicious.append(domain)
    return suspicious


def calculate_risk_score(parsed_email: dict, iocs: dict) -> dict:
    """
    Función principal — aplica todas las reglas y calcula el risk score.
    Devuelve el score y las razones que lo justifican.
    """
    score = 0
    reasons = []

    body = parsed_email.get("body", "")
    sender = parsed_email.get("sender", "")
    reply_to = parsed_email.get("reply_to", "")
    domains = iocs.get("domains", [])

    # Regla 1 — lenguaje urgente (15 puntos)
    triggered, found_words = check_urgent_language(body)
    if triggered:
        score += 15
        reasons.append(f"Lenguaje urgente detectado: {', '.join(found_words[:3])}")

    # Regla 2 — petición de credenciales (25 puntos)
    triggered, found_words = check_credential_request(body)
    if triggered:
        score += 25
        reasons.append(f"Petición de credenciales: {', '.join(found_words[:3])}")

    # Regla 3 — spoofing del sender (25 puntos)
    if check_spoofed_sender(sender, reply_to):
        score += 25
        reasons.append("Reply-To diferente al remitente — posible spoofing")

    # Regla 4 — dominios sospechosos (20 puntos)
    suspicious = check_suspicious_domains(domains)
    if suspicious:
        score += 20
        reasons.append(f"Dominios sospechosos: {', '.join(suspicious)}")

    # Regla 5 — URLs en el email (5 puntos)
    if len(iocs.get("urls", [])) > 3:
        score += 5
        reasons.append(f"Alto número de URLs: {len(iocs['urls'])}")

    # Regla 6 — TLD sospechoso (15 puntos)
    for domain in domains:
        if any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS):
            score += 15
            reasons.append(f"TLD sospechoso detectado: {domain}")
            break

    # Regla 7 — adjuntos peligrosos (20 puntos)
    attachments = iocs.get("attachments", [])
    dangerous = [a for a in attachments if any(a.endswith(ext) for ext in DANGEROUS_EXTENSIONS)]
    if dangerous:
        score += 20
        reasons.append(f"Adjuntos peligrosos: {', '.join(dangerous)}")  

    # Calculamos severidad según el score
    if score >= 75:
        severity = "critical"
    elif score >= 50:
        severity = "high"
    elif score >= 25:
        severity = "medium"
    else:
        severity = "low"

    return {
        "score":    score,
        "severity": severity,
        "reasons":  reasons
    }