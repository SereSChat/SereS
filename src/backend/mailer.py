"""Sending e-mails (password reset links) through an SMTP server.

Configured with environment variables (e.g. in src/backend/.env):

    SMTP_HOST       mail server, e.g. localhost or mail.example.com (unset = e-mail disabled)
    SMTP_PORT       default 587 (25 for a local Postfix, 465 for SMTPS)
    SMTP_SECURITY   starttls (default), ssl or none
    SMTP_USER       optional login
    SMTP_PASSWORD   optional password
    MAIL_FROM       sender, e.g. "SereS <no-reply@example.com>"
    MAIL_DEBUG=1    print mails to the console instead of sending them (development)
"""

import os
import smtplib
import ssl
import threading
from email.message import EmailMessage
from email.utils import formatdate, make_msgid


def debug_mode():
    return os.getenv("MAIL_DEBUG") == "1"


def configured():
    return debug_mode() or bool(os.getenv("SMTP_HOST"))


def sender():
    return os.getenv("MAIL_FROM") or "SereS <no-reply@localhost>"


def build_message(to, subject, text):
    message = EmailMessage()
    message["From"] = sender()
    message["To"] = to
    message["Subject"] = subject
    message["Date"] = formatdate(localtime=False)
    domain = sender().rsplit("@", 1)[-1].strip("> ") or "localhost"
    message["Message-ID"] = make_msgid(domain=domain)
    message.set_content(text)
    return message


def deliver(message):
    if debug_mode():
        print("----- MAIL_DEBUG -----\n" + message.as_string() + "\n----------------------", flush=True)
        return
    host = os.getenv("SMTP_HOST")
    port = int(os.getenv("SMTP_PORT", "587"))
    security = os.getenv("SMTP_SECURITY", "starttls").lower()
    context = ssl.create_default_context()
    if security == "ssl":
        client = smtplib.SMTP_SSL(host, port, context=context, timeout=20)
    else:
        client = smtplib.SMTP(host, port, timeout=20)
    with client:
        if security == "starttls":
            client.starttls(context=context)
        user = os.getenv("SMTP_USER")
        if user:
            client.login(user, os.getenv("SMTP_PASSWORD", ""))
        client.send_message(message)


def send_async(to, subject, text):
    """Sends in the background so the response time does not reveal whether an account exists."""

    def run():
        try:
            deliver(build_message(to, subject, text))
        except Exception as e:  # a failed mail must never break the request
            print("sending mail failed:", type(e).__name__, e, flush=True)

    threading.Thread(target=run, daemon=True).start()
