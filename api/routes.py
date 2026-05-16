from fastapi import APIRouter, HTTPException
from schemas.analysis import EmailInput, AnalysisResponse
from core.parser import parse_email
from core.ioc_extractor import extract_iocs
from core.risk_engine import calculate_risk_score
from core.llm_analyzer import analyze_with_llm
from db.repository import save_analysis, already_analyzed

router = APIRouter()


@router.post("/analyze", response_model=AnalysisResponse)
async def analyze_email(request: EmailInput):
    """
    Endpoint principal — recibe un email_id de Gmail,
    lo analiza y devuelve el resultado estructurado.
    """
    try:
        # 1. Comprobar si ya fue analizado
        if already_analyzed(request.email_id):
            raise HTTPException(
                status_code=400,
                detail="Este email ya fue analizado anteriormente"
            )

        # 2. Aquí irá la llamada a Gmail API (por implementar)
        raw_email = {}  # placeholder por ahora

        # 3. Pipeline de análisis
        parsed    = parse_email(raw_email)
        iocs      = extract_iocs(parsed)
        risk      = calculate_risk_score(parsed, iocs)
        llm_result = analyze_with_llm(parsed, iocs, risk)

        # 4. Construir respuesta completa
        result = {
            "email_id": request.email_id,
            "subject":  parsed["subject"],
            "sender":   parsed["sender"],
            **llm_result,
            "iocs":     iocs,
        }

        # 5. Guardar en base de datos
        save_analysis(result)

        return result

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/analyses", response_model=list[AnalysisResponse])
async def get_recent():
    """Devuelve los últimos 10 análisis realizados."""
    from db.repository import get_recent_analyses
    return get_recent_analyses()