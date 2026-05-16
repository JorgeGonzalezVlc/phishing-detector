from fastapi import FastAPI
from api.routes import router
from db.repository import init_db

# Inicializamos la aplicación FastAPI
app = FastAPI(
    title="Phishing Detector API",
    description="Sistema de detección inteligente de phishing mediante IA",
    version="1.0.0"
)

# Registramos las rutas
app.include_router(router, prefix="/api/v1")


@app.on_event("startup")
async def startup():
    """Se ejecuta al arrancar la aplicación."""
    init_db()
    print("Base de datos inicializada")
    print("Phishing Detector API arrancada")


@app.get("/")
async def root():
    """Health check — comprueba que la API está viva."""
    return {"status": "ok", "message": "Phishing Detector API funcionando"}