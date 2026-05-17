from dotenv import load_dotenv
import os

load_dotenv()

# Anthropic
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY")

# Gmail
GMAIL_CLIENT_ID = os.getenv("GMAIL_CLIENT_ID")
GMAIL_CLIENT_SECRET = os.getenv("GMAIL_CLIENT_SECRET")

# Virus Total
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

# Validación al arrancar
required_vars = ["ANTHROPIC_API_KEY", "VIRUSTOTAL_API_KEY"]

for var in required_vars:
    if not os.getenv(var):
        raise EnvironmentError(f"Variable de entorno no encontrada: {var}")