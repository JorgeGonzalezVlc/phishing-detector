from fastapi import APIRouter, HTTPException
from schemas.analysis import EmailInput, AnalysisResponse
from core.parser import parse_email
from core.ioc_extractor import extract_iocs
from core.risk_engine import calculate_risk_score
from core.llm_analyzer import analyze_with_llm
from core.gmail_client import get_gmail_service
from db.repository import save_analysis, already_analyzed

router = APIRouter()


def normalize_email_id(email_id: str) -> str:
    """Convierte el ID largo decimal de Gmail al formato hexadecimal corto."""
    if email_id.isdigit():
        return hex(int(email_id))[2:]
    return email_id


@router.post("/analyze", response_model=AnalysisResponse)
async def analyze_email(request: EmailInput):
    try:
        # Normalizar el ID — acepta tanto decimal como hexadecimal
        email_id = normalize_email_id(request.email_id)

        # 1. Comprobar si ya fue analizado
        if already_analyzed(email_id):
            raise HTTPException(
                status_code=400,
                detail="Este email ya fue analizado anteriormente"
            )

        # 2. Obtener email real de Gmail
        service = get_gmail_service()
        raw_email = service.users().messages().get(
            userId="me",
            id=email_id,
            format="full"
        ).execute()

        # 3. Pipeline de análisis
        parsed    = parse_email(raw_email)
        iocs      = extract_iocs(parsed)
        risk      = calculate_risk_score(parsed, iocs)

        # VirusTotal
        vt_results = []
        if iocs.get("urls"):
            from core.virustotal import check_urls
            vt_results = check_urls(iocs["urls"])

        result = analyze_with_llm(parsed, iocs, risk, vt_results)

        # 4. Construir respuesta completa
        full_result = {
            "email_id": email_id,
            "subject":  parsed["subject"],
            "sender":   parsed["sender"],
            **result,
            "iocs":     iocs,
        }

        # 5. Guardar en base de datos
        save_analysis(full_result)

        return full_result

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/analyses", response_model=list[AnalysisResponse])
async def get_recent():
    from db.repository import get_recent_analyses
    return get_recent_analyses()