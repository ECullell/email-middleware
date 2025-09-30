"""Minimal email relay service for business card contact forms."""
from __future__ import annotations

import logging
import os
import smtplib
import ssl
import time
from collections import defaultdict, deque
from email.message import EmailMessage
from email.utils import parseaddr
from functools import wraps
import re
from threading import Lock
from typing import Deque, Dict, List
from werkzeug.middleware.proxy_fix import ProxyFix

from flask import Flask, jsonify, request
from flask_cors import CORS

# Flask app setup
app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 25 * 1024  # 25 KiB payload cap
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)

# Logging configuration
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
)
logger = logging.getLogger("email-relay")

# CORS configuration
DEFAULT_CORS_ORIGINS = ["https://enric-cullell.github.io"]
raw_origins = os.getenv("CORS_ORIGINS")
if raw_origins:
    origins = [origin.strip() for origin in raw_origins.split(",") if origin.strip()]
else:
    origins = DEFAULT_CORS_ORIGINS

CORS(
    app,
    resources={
        r"/send": {"origins": origins, "methods": ["POST"]},
        r"/health": {"origins": origins, "methods": ["GET"]},
    },
    max_age=86400,
)

# Rate limiting state
RATE_LIMIT_MAX_REQUESTS = 10
RATE_LIMIT_WINDOW_SECONDS = 10 * 60
_rate_limits: Dict[str, Deque[float]] = defaultdict(deque)
_rate_limit_lock = Lock()


def _client_ip() -> str:
    """Resolve client IP (ProxyFix applied)."""
    return request.remote_addr or "unknown"


def rate_limited(func):
    """Simple sliding-window rate limiting decorator."""

    @wraps(func)
    def wrapper(*args, **kwargs):
        ip = _client_ip()
        now = time.time()
        with _rate_limit_lock:
            timestamps = _rate_limits[ip]
            # Drop timestamps outside the window
            while timestamps and now - timestamps[0] > RATE_LIMIT_WINDOW_SECONDS:
                timestamps.popleft()
            if len(timestamps) >= RATE_LIMIT_MAX_REQUESTS:
                logger.warning("Rate limit exceeded for %s", ip)
                return error_response("Too many requests", 429)
            timestamps.append(now)
        return func(*args, **kwargs)

    return wrapper


@app.after_request
def log_response(response):
    logger.info(
        "%s %s -> %s for %s",
        request.method,
        request.path,
        response.status_code,
        _client_ip(),
    )
    return response


def error_response(message: str, status_code: int):
    return jsonify({"error": message}), status_code


def ok_response():
    return jsonify({"ok": True})


def coerce_bool(value) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on"}
    if isinstance(value, (int, float)):
        return bool(value)
    return False


EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

def clean_email(value: str) -> str:
    value = (value or "").strip()
    # prevent header injection
    if "\r" in value or "\n" in value:
        return ""
    name, addr = parseaddr(value)
    if not EMAIL_RE.match(addr or ""):
        return ""
    return addr


def build_email(data: dict, smtp_user: str, mail_to: List[str]) -> EmailMessage:
    card_id = data.get("cardId") or "Business Card"
    subject = f"[{card_id}] New inquiry"
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = smtp_user
    msg["To"] = ", ".join(mail_to)
    msg["Reply-To"] = data["email"]

    body_lines = [
        f"Name: {data['name']}",
        f"Email: {data['email']}",
        f"Phone: {data.get('phone','-')}",
        f"Company: {data.get('company','-')}",
        f"Consent: {'Yes' if data['consent'] else 'No'}",
        f"Card ID: {data.get('cardId','-')}",
        "-" * 40,
        "Question:",
        data['question'],
    ]
    msg.set_content("\n".join(body_lines))
    return msg


@app.route("/health", methods=["GET"])
def health():
    return ok_response()


@app.route("/send", methods=["POST"])
@rate_limited
def send():
    raw_payload = request.get_json(silent=True)
    if raw_payload is None:
        return error_response("Invalid JSON payload", 400)
    if not isinstance(raw_payload, dict):
        return error_response("Payload must be a JSON object", 400)

    expected_fields = {
        "name",
        "email",
        "phone",
        "company",
        "question",
        "consent",
        "_honey",
        "cardId",
    }
    payload = {}
    for key in expected_fields:
        value = raw_payload.get(key)
        if isinstance(value, str):
            payload[key] = value.strip()
        else:
            payload[key] = value
    payload["email"] = clean_email(payload.get("email", ""))
    # Honeypot: exit silently
    if payload.get("_honey"):
        logger.info("Honeypot triggered by %s", _client_ip())
        return ok_response()

    required_fields = ["name", "email", "question", "consent"]
    missing = [field for field in required_fields if not payload.get(field)]
    if missing:
        return error_response(f"Missing required field(s): {', '.join(missing)}", 400)
    if not payload["email"]:
        return error_response("Invalid email", 400)

    payload["consent"] = coerce_bool(payload["consent"])
    if not payload["consent"]:
        return error_response("Consent is required", 400)

    smtp_user = os.getenv("SMTP_USER")
    smtp_pass = os.getenv("SMTP_PASS")
    if not smtp_user or not smtp_pass:
        logger.error("SMTP credentials not configured")
        return error_response("Mailer not configured", 500)

    mail_to_raw = os.getenv("MAIL_TO", smtp_user)
    mail_to = [addr.strip() for addr in mail_to_raw.split(",") if addr.strip()]

    try:
        email_message = build_email(payload, smtp_user, mail_to)
        context = ssl.create_default_context()
        with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=context, timeout=15) as client:
            client.login(smtp_user, smtp_pass)
            client.send_message(email_message)
    except smtplib.SMTPAuthenticationError as e:
        logger.exception("SMTP authentication failed: %s", getattr(e, 'smtp_error', b'').decode(errors='ignore') if hasattr(e, 'smtp_error') else '')
        return error_response("Mailer failed", 500)
    except (smtplib.SMTPException, OSError) as e:
        logger.exception("SMTP send failed: %s", str(e))
        return error_response("Mailer failed", 500)

    return ok_response()


def create_app():
    """App factory for WSGI servers."""
    return app


if __name__ == "__main__":
    port = int(os.getenv("PORT", "3000"))
    app.run(host="0.0.0.0", port=port)
