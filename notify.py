import requests, smtplib
from email.message import EmailMessage
from typing import Optional
from vulnez import config

def send_slack(message: str, webhook: Optional[str] = None) -> bool:
    url = webhook or config.SLACK_WEBHOOK
    if not url:
        return False
    payload = { 'text': message }
    try:
        r = requests.post(url, json=payload, timeout=10)
        return r.status_code == 200
    except Exception:
        return False

def send_email(subject: str, body: str, to: str) -> bool:
    if not config.SMTP_SERVER or not config.SMTP_USER:
        return False
    msg = EmailMessage()
    msg['From'] = config.SMTP_USER
    msg['To'] = to
    msg['Subject'] = subject
    msg.set_content(body)
    try:
        with smtplib.SMTP(config.SMTP_SERVER, config.SMTP_PORT) as s:
            s.starttls()
            s.login(config.SMTP_USER, config.SMTP_PASS)
            s.send_message(msg)
        return True
    except Exception:
        return False
