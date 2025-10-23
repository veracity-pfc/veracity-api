from __future__ import annotations
import html
import httpx
from ..core.config import settings

RESEND_API = "https://api.resend.com/emails"

class EmailError(RuntimeError):
    pass

async def send_email(to: str, subject: str, html_body: str) -> None:
    payload = {
        "from": settings.resend_from,
        "to": [to],
        "subject": subject,
        "html": html_body,
    }
    headers = {"Authorization": f"Bearer {settings.resend_api_key}"}

    async with httpx.AsyncClient(timeout=15) as client:
        r = await client.post(RESEND_API, json=payload, headers=headers)
        if r.status_code >= 400:
            try:
                err = r.json()
            except Exception:
                err = {"error": r.text}
            raise EmailError(f"Falha ao enviar e-mail: {err}")

def verification_email_html(name: str, code: str) -> str:
    name = html.escape(name or "")
    code_fmt = " ".join(html.escape(code))  
    return f"""
<!doctype html>
<html>
  <body style="font-family:Arial,sans-serif;background:#0b1211;padding:24px;color:#eef2f1">
    <div style="max-width:520px;margin:0 auto;background:#0e1b19;border-radius:12px;padding:24px">
      <h2 style="margin:0 0 8px">Confirme seu e-mail</h2>
      <p style="opacity:.9">Olá, <b>{name}</b>. Confirme seu endereço de e-mail informando o código abaixo na plataforma Veracity.
      </br>Ele expira em <b>10 minutos</b>.</p>
      <div style="letter-spacing:.5rem;font-size:28px;font-weight:700;background:#0f2c27;
                  padding:14px 18px;border-radius:10px;display:inline-block;margin:12px 0">
        {code_fmt}
      </div>
      <p style="opacity:.8">Se você não solicitou este código, pode ignorar esta mensagem com segurança.</br>Por favor, não compartilhe este código com ninguém.</p>
    </div>
  </body>
</html>
    """.strip()
    

def reset_password_email_html(name: str, link: str) -> str:
    name = html.escape(name or "")
    link = html.escape(link)
    return f"""
<!doctype html>
<html>
  <body style="font-family:Arial,sans-serif;background:#0b1211;padding:24px;color:#eef2f1">
    <div style="max-width:520px;margin:0 auto;background:#0e1b19;border-radius:12px;padding:24px">
      <h2 style="margin:0 0 8px">Redefinir senha</h2>
      <p style="opacity:.9">Olá, <b>{name}</b>. Você solicitou a redefinição da sua senha no Veracity.</p>
      <p style="opacity:.9">Clique no botão abaixo para criar uma nova senha. O link expira em <b>30 minutos</b>.</p>
      <p><a href="{link}" style="display:inline-block;background:#1c6a58;color:#fff;padding:12px 18px;border-radius:10px;text-decoration:none;font-weight:700">Redefinir senha</a></p>
      <p style="opacity:.8">Se você não solicitou, ignore este e-mail.</p>
    </div>
  </body>
</html>
    """.strip()

