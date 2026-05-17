import requests
import time
from config import VIRUSTOTAL_API_KEY

BASE_URL = "https://www.virustotal.com/api/v3"

HEADERS = {
    "x-apikey": VIRUSTOTAL_API_KEY
}


def check_url(url: str) -> dict:
    """Analiza una URL contra la base de datos de VirusTotal."""
    try:
        response = requests.post(
            f"{BASE_URL}/urls",
            headers=HEADERS,
            data={"url": url}
        )

        if response.status_code != 200:
            return {"error": f"Error enviando URL: {response.status_code}"}

        analysis_id = response.json()["data"]["id"]
        time.sleep(2)

        result = requests.get(
            f"{BASE_URL}/analyses/{analysis_id}",
            headers=HEADERS
        )

        if result.status_code != 200:
            return {"error": f"Error obteniendo resultado: {result.status_code}"}

        stats = result.json()["data"]["attributes"]["stats"]

        malicious  = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless   = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)
        total      = malicious + suspicious + harmless + undetected

        # Score de 0 a 100 basado en proporción de motores que la marcan
        vt_score = 0
        if total > 0:
            vt_score = round(((malicious * 1.0) + (suspicious * 0.5)) / total * 100)

        return {
            "url":        url,
            "malicious":  malicious,
            "suspicious": suspicious,
            "harmless":   harmless,
            "undetected": undetected,
            "total_engines": total,
            "vt_score":   vt_score,
            "is_malicious": malicious > 0 or suspicious > 2
        }

    except Exception as e:
        return {"error": str(e)}
        

def check_urls(urls: list) -> list:
    """Analiza una lista de URLs contra VirusTotal."""
    results = []
    for url in urls[:5]:  # máximo 5 URLs
        result = check_url(url)
        results.append(result)
        time.sleep(1)
    return results