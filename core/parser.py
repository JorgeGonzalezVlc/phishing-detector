import base64
from bs4 import BeautifulSoup


def get_header(headers: list, name: str) -> str:
    """Busca un header específico por nombre."""
    for header in headers:
        if header["name"].lower() == name.lower():
            return header["value"]
    return ""


def decode_body(part: dict) -> str:
    """Decodifica el cuerpo del email de base64 a texto."""
    data = part.get("body", {}).get("data", "")
    if data:
        decoded = base64.urlsafe_b64decode(data + "==").decode("utf-8", errors="ignore")
        return decoded
    return ""


def extract_body(payload: dict) -> dict:
    """Extrae el cuerpo en texto plano y HTML."""
    plain = ""
    html = ""

    mime_type = payload.get("mimeType", "")

    if mime_type == "text/plain":
        plain = decode_body(payload)
    elif mime_type == "text/html":
        html = decode_body(payload)
    elif "parts" in payload:
        for part in payload["parts"]:
            result = extract_body(part)
            plain += result["plain"]
            html += result["html"]

    return {"plain": plain, "html": html}


def html_to_text(html: str) -> str:
    """Convierte HTML a texto plano limpio."""
    if not html:
        return ""
    soup = BeautifulSoup(html, "html.parser")
    return soup.get_text(separator=" ", strip=True)


def parse_email(raw_email: dict) -> dict:
    """
    Recibe un email crudo de la Gmail API y devuelve
    un diccionario estructurado con toda la información relevante.
    """
    payload = raw_email.get("payload", {})
    headers = payload.get("headers", [])

    body = extract_body(payload)
    plain_text = body["plain"] or html_to_text(body["html"])

    return {
        "id":        raw_email.get("id", ""),
        "subject":   get_header(headers, "Subject"),
        "sender":    get_header(headers, "From"),
        "reply_to":  get_header(headers, "Reply-To"),
        "date":      get_header(headers, "Date"),
        "headers":   headers,
        "body":      plain_text,
        "html":      body["html"],
    }