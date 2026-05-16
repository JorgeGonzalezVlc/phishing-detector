import re
import tldextract


# Patrones regex para extraer IOCs
URL_PATTERN = re.compile(r'https?://[^\s<>"{}|\\^`\[\]]+')
IP_PATTERN = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
EMAIL_PATTERN = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')


def extract_urls(text: str) -> list:
    """Extrae todas las URLs del texto."""
    return list(set(URL_PATTERN.findall(text)))


def extract_ips(headers: list) -> list:
    """Extrae IPs de los headers del email."""
    ips = []
    for header in headers:
        found = IP_PATTERN.findall(header["value"])
        ips.extend(found)
    return list(set(ips))


def extract_domains(urls: list) -> list:
    """Extrae los dominios raíz de una lista de URLs."""
    domains = []
    for url in urls:
        extracted = tldextract.extract(url)
        if extracted.domain and extracted.suffix:
            domain = f"{extracted.domain}.{extracted.suffix}"
            domains.append(domain)
    return list(set(domains))


def extract_sender_domain(sender: str) -> str:
    """Extrae el dominio del remitente."""
    match = EMAIL_PATTERN.search(sender)
    if match:
        email = match.group()
        return email.split("@")[1]
    return ""


def extract_iocs(parsed_email: dict) -> dict:
    """
    Función principal — extrae todos los IOCs del email parseado.
    IOC = Indicator of Compromise
    """
    body = parsed_email.get("body", "")
    html = parsed_email.get("html", "")
    headers = parsed_email.get("headers", [])
    sender = parsed_email.get("sender", "")

    # Extraemos de body y html combinados
    full_text = body + " " + html

    urls = extract_urls(full_text)
    domains = extract_domains(urls)

    return {
        "urls":          urls,
        "ips":           extract_ips(headers),
        "domains":       domains,
        "sender_domain": extract_sender_domain(sender),
        "emails":        list(set(EMAIL_PATTERN.findall(full_text))),
    }