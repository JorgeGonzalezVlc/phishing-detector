import os
import pickle
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build

SCOPES = [
    "https://www.googleapis.com/auth/gmail.readonly",
    "https://www.googleapis.com/auth/gmail.modify",
    "https://www.googleapis.com/auth/gmail.send",
    "https://www.googleapis.com/auth/gmail.labels",
]

CREDENTIALS_FILE = "credentials.json"
TOKEN_FILE = "token.pickle"


def get_credentials() -> Credentials:
    """Gestiona el flujo OAuth2 y devuelve credenciales válidas."""
    creds = None

    # Si ya tenemos token guardado lo cargamos
    if os.path.exists(TOKEN_FILE):
        with open(TOKEN_FILE, "rb") as f:
            creds = pickle.load(f)

    # Si no hay token válido lanzamos el flujo OAuth
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(
                CREDENTIALS_FILE, SCOPES
            )
            creds = flow.run_local_server(port=0)

        # Guardamos el token para próximas ejecuciones
        with open(TOKEN_FILE, "wb") as f:
            pickle.dump(creds, f)

    return creds


def get_gmail_service():
    """Devuelve el cliente de Gmail API autenticado."""
    creds = get_credentials()
    return build("gmail", "v1", credentials=creds)


def fetch_unread_emails(max_results: int = 10) -> list:
    """Obtiene los emails no leídos de la bandeja de entrada."""
    service = get_gmail_service()

    results = service.users().messages().list(
        userId="me",
        labelIds=["INBOX", "UNREAD"],
        maxResults=max_results
    ).execute()

    messages = results.get("messages", [])
    emails = []

    for msg in messages:
        email = service.users().messages().get(
            userId="me",
            id=msg["id"],
            format="full"
        ).execute()
        emails.append(email)

    return emails


def mark_as_read(email_id: str):
    """Marca un email como leído."""
    service = get_gmail_service()
    service.users().messages().modify(
        userId="me",
        id=email_id,
        body={"removeLabelIds": ["UNREAD"]}
    ).execute()


def move_to_label(email_id: str, label_name: str):
    """Mueve un email a una etiqueta/carpeta específica."""
    service = get_gmail_service()

    # Buscamos si la etiqueta ya existe
    labels = service.users().labels().list(userId="me").execute()
    label_id = None

    for label in labels.get("labels", []):
        if label["name"].lower() == label_name.lower():
            label_id = label["id"]
            break

    # Si no existe la creamos
    if not label_id:
        new_label = service.users().labels().create(
            userId="me",
            body={"name": label_name}
        ).execute()
        label_id = new_label["id"]

    # Movemos el email
    service.users().messages().modify(
        userId="me",
        id=email_id,
        body={"addLabelIds": [label_id]}
    ).execute()