from core.gmail_client import fetch_unread_emails
from core.parser import parse_email

print("🔐 Conectando con Gmail...")

emails = fetch_unread_emails(max_results=3)

print(f"📬 {len(emails)} emails no leídos encontrados\n")

for raw_email in emails:
    parsed = parse_email(raw_email)
    print(f"De:      {parsed['sender']}")
    print(f"Asunto:  {parsed['subject']}")
    print(f"Fecha:   {parsed['date']}")
    print("-" * 50)