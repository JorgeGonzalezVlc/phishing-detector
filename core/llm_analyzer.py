import json
import os
from anthropic import Anthropic
from config import ANTHROPIC_API_KEY

client = Anthropic(api_key=ANTHROPIC_API_KEY)

# Leemos el prompt una sola vez al cargar el módulo
PROMPT_PATH = os.path.join("prompts", "phishing_analysis.txt")
with open(PROMPT_PATH, "r", encoding="utf-8") as f:
    PROMPT_TEMPLATE = f.read()


def analyze_with_llm(parsed_email: dict, iocs: dict, risk: dict, vt_results: list = []) -> dict:
    
    # Resumimos los resultados de VirusTotal para el prompt
    vt_summary = []
    for vt in vt_results:
        if "error" not in vt:
            vt_summary.append(f"{vt['url'][:50]} → score: {vt['vt_score']}/100 (maliciosos: {vt['malicious']})")
    
    vt_text = "\n".join(vt_summary) if vt_summary else "No se analizaron URLs"

    prompt = PROMPT_TEMPLATE.format(
        sender             = parsed_email.get("sender", "N/A"),
        reply_to           = parsed_email.get("reply_to", "N/A"),
        subject            = parsed_email.get("subject", "N/A"),
        date               = parsed_email.get("date", "N/A"),
        body               = parsed_email.get("body", "N/A")[:2000],
        urls               = iocs.get("urls", []),
        ips                = iocs.get("ips", []),
        domains            = iocs.get("domains", []),
        sender_domain      = iocs.get("sender_domain", "N/A"),
        emails             = iocs.get("emails", []),
        risk_score         = risk.get("score", 0),
        severity           = risk.get("severity", "N/A"),
        reasons            = risk.get("reasons", []),
        recommended_action = risk.get("recommended_action", "review"),
        vt_results         = vt_text,
    )

    response = client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=1000,
        messages=[
            {"role": "user", "content": prompt}
        ]
    )

    text = response.content[0].text.strip()

    # Extraer solo el bloque JSON por si Claude añade texto extra
    start = text.find("{")
    end = text.rfind("}") + 1
    text = text[start:end]

    result = json.loads(text)
    return result