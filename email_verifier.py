"""
Email Verification API
======================
Built with FastAPI + Python

SETUP (run these in your terminal first):
    pip install fastapi uvicorn dnspython

RUN:
    uvicorn email_verifier:app --reload

THEN OPEN:
    http://127.0.0.1:8000/docs   <-- interactive docs (try it right from the browser!)

USAGE:
    GET http://127.0.0.1:8000/verify?email=someone@example.com
"""

import re
import smtplib
import socket
import dns.resolver
from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from typing import Optional

app = FastAPI(
    title="Email Verification API",
    description="Checks if an email address is real using format, domain, and SMTP mailbox checks.",
    version="1.0.0"
)


# ─── Response Model ───────────────────────────────────────────────────────────

class VerificationResult(BaseModel):
    email: str
    format_valid: bool
    domain_exists: bool
    mailbox_exists: Optional[bool]   # None means "unverifiable" (e.g. Gmail blocks this)
    status: str                      # "valid" | "invalid" | "unverifiable"
    reason: str


# ─── Helper Functions ─────────────────────────────────────────────────────────

def check_format(email: str) -> bool:
    """Check if the email has a valid format."""
    pattern = r'^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))


def get_mx_records(domain: str) -> list:
    """Look up MX records for the domain. Returns a list of mail servers."""
    try:
        records = dns.resolver.resolve(domain, 'MX')
        # Sort by priority (lowest number = highest priority)
        return sorted(records, key=lambda r: r.preference)
    except Exception:
        return []


def check_smtp_mailbox(email: str, mx_records: list) -> Optional[bool]:
    """
    Try to verify the mailbox exists via SMTP.
    Returns:
        True  - mailbox confirmed to exist
        False - mailbox confirmed not to exist
        None  - server blocked the check (unverifiable)
    """
    domain = email.split("@")[1].lower()

    # These major providers block SMTP probing, so we skip them
    UNVERIFIABLE_DOMAINS = {
        "gmail.com", "googlemail.com",
        "yahoo.com", "yahoo.co.uk", "ymail.com",
        "outlook.com", "hotmail.com", "live.com", "msn.com",
        "icloud.com", "me.com", "mac.com",
        "protonmail.com", "proton.me",
        "aol.com"
    }

    if domain in UNVERIFIABLE_DOMAINS:
        return None  # Can't verify, but domain is known/real

    if not mx_records:
        return False

    # Try each mail server until one works
    for record in mx_records:
        mx_host = str(record.exchange).rstrip(".")
        try:
            with smtplib.SMTP(timeout=10) as smtp:
                smtp.connect(mx_host, 25)
                smtp.helo("verify.example.com")
                smtp.mail("verify@verify.example.com")
                code, _ = smtp.rcpt(email)

                if code == 250:
                    return True   # Mailbox exists
                elif code == 550:
                    return False  # Mailbox does not exist
                else:
                    return None   # Inconclusive response
        except (smtplib.SMTPConnectError, socket.timeout, ConnectionRefusedError):
            continue  # Try the next MX server
        except Exception:
            return None  # Something unexpected happened

    return None  # All servers tried, no conclusive result


# ─── Main Endpoint ────────────────────────────────────────────────────────────

@app.get("/verify", response_model=VerificationResult)
def verify_email(email: str):
    """
    Verify whether an email address is real.

    - **email**: The email address to check (e.g. someone@company.com)
    """
    email = email.strip().lower()

    # Step 1: Format check
    if not check_format(email):
        return VerificationResult(
            email=email,
            format_valid=False,
            domain_exists=False,
            mailbox_exists=False,
            status="invalid",
            reason="Email format is invalid."
        )

    domain = email.split("@")[1]

    # Step 2: Domain / MX record check
    mx_records = get_mx_records(domain)
    domain_exists = len(mx_records) > 0

    if not domain_exists:
        return VerificationResult(
            email=email,
            format_valid=True,
            domain_exists=False,
            mailbox_exists=False,
            status="invalid",
            reason=f"Domain '{domain}' has no mail servers. It cannot receive emails."
        )

    # Step 3: SMTP mailbox check
    mailbox_exists = check_smtp_mailbox(email, mx_records)

    if mailbox_exists is True:
        return VerificationResult(
            email=email,
            format_valid=True,
            domain_exists=True,
            mailbox_exists=True,
            status="valid",
            reason="Email address exists and can receive mail."
        )
    elif mailbox_exists is False:
        return VerificationResult(
            email=email,
            format_valid=True,
            domain_exists=True,
            mailbox_exists=False,
            status="invalid",
            reason="Mailbox does not exist on the mail server."
        )
    else:
        return VerificationResult(
            email=email,
            format_valid=True,
            domain_exists=True,
            mailbox_exists=None,
            status="unverifiable",
            reason="Domain exists and accepts email, but the mail server does not allow mailbox-level verification. "
                   "This is common with Gmail, Yahoo, Outlook, and many business servers."
        )


# ─── Health Check ─────────────────────────────────────────────────────────────
# ─── Health Check ─────────────────────────────────────────────────────────────

# Serve static files (web UI)
app.mount("/static", StaticFiles(directory="static"), name="static")

@app.get("/experience", include_in_schema=False)
def experience():
    return FileResponse("static/index.html")
