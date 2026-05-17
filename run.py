from core.gmail_client import fetch_unread_emails, move_to_label, mark_as_read
from core.parser import parse_email
from core.ioc_extractor import extract_iocs
from core.risk_engine import calculate_risk_score
from core.llm_analyzer import analyze_with_llm
from db.repository import init_db, save_analysis, already_analyzed
import json

# Mapa de acciones a etiquetas de Gmail
LABEL_MAP = {
    "delete":    "Phishing/Eliminado",
    "quarantine": "Phishing/Cuarentena",
    "escalate":  "Phishing/Revisar",
    "review":    "Phishing/Revisar",
    "safe":      None  # no se mueve
}


def process_email(raw_email: dict):
    """Procesa un email completo a través del pipeline."""

    # 1. Parsear
    parsed = parse_email(raw_email)
    email_id = parsed["id"]

    print(f"\n Analizando: {parsed['subject'][:60]}")
    print(f"   De: {parsed['sender']}")

    # 2. Comprobar si ya fue analizado
    if already_analyzed(email_id):
        print("   ⏭️  Ya analizado anteriormente, saltando...")
        return

    # 3. Pipeline de análisis
    iocs       = extract_iocs(parsed)
    risk       = calculate_risk_score(parsed, iocs)

    # VirusTotal — analizar URLs si las hay
    vt_results = []
    if iocs.get("urls"):
        from core.virustotal import check_urls
        vt_results = check_urls(iocs["urls"])

    result = analyze_with_llm(parsed, iocs, risk, vt_results)

    # 4. Mostrar resultado
    print(f"    Clasificación:  {result['classification']}")
    print(f"    Risk Score:     {result['risk_score']}/100")
    print(f"    Severidad:      {result['severity']}")
    print(f"    MITRE:          {result['mitre_technique']}")
    print(f"    VirusTotal:     {result['virus_total_score']}/100")
    print(f"    Acción:         {result['recommended_action']}")

    # 5. Guardar en base de datos
    save_analysis({
        "email_id":             email_id,
        "subject":              parsed["subject"],
        "sender":               parsed["sender"],
        "classification":       result["classification"],
        "risk_score":           result["risk_score"],
        "severity":             result["severity"],
        "mitre_technique":      result["mitre_technique"],
        "mitre_technique_name": result["mitre_technique_name"],
        "attack_summary":       result["attack_summary"],
        "recommended_action":   result["recommended_action"],
        "reasons":              result["reasons"],
        "iocs":                 dict(iocs),
    })

    # 6. Actuar según la recomendación
    label = LABEL_MAP.get(result["recommended_action"])
    if label:
        move_to_label(email_id, label)
        print(f"   📁 Movido a: {label}")

    mark_as_read(email_id)


def main():
    print("🛡️  Phishing Detector arrancando...\n")
    init_db()

    print("📬 Obteniendo emails no leídos...")
    emails = fetch_unread_emails(max_results=10)
    print(f"   {len(emails)} emails encontrados\n")

    for raw_email in emails:
        try:
            process_email(raw_email)
        except Exception as e:
            print(f"   ❌ Error procesando email: {e}")

    print("\n✅ Análisis completado")


if __name__ == "__main__":
    main()