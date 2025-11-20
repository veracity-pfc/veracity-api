from __future__ import annotations

import html

import httpx

from app.core.config import settings
from app.core.constants import RESEND_API


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


def build_contact_email_html(email: str, subject: str, message: str) -> str:
    return (
        "<!doctype html><html><body style='font-family:Arial,sans-serif'>"
        f"<h2>Nova mensagem recebida - {html.escape(subject)}</h2>"
        f"<p><b>De:</b> {html.escape(email)}</p>"
        "<hr>"
        f"<pre style='white-space:pre-wrap;font-size:14px;line-height:1.5'>"
        f"{html.escape(message)}"
        "</pre>"
        "</body></html>"
    )


def build_api_token_request_email_html(
    email: str,
    created_at: str,
    request_id: str,
) -> str:
    body = (
        "Nova solicitação de token de API\n\n"
        f"Solicitação criada em: {created_at}\n"
        f"Usuário solicitante: {email}\n\n"
        f"Para mais detalhes, consulte o link: http://localhost:5173/request/{request_id}"
    )
    return (
        "<!doctype html><html><body style='font-family:Arial,sans-serif'>"
        f"<pre style='white-space:pre-wrap;font-size:14px;line-height:1.5'>"
        f"{html.escape(body)}"
        "</pre>"
        "</body></html>"
    )


def build_api_token_approved_email_html() -> str:
    body = (
        "Seu token de API foi gerado com sucesso.\n\n"
        "Você já pode visualizá-lo na tela de perfil do Veracity. "
        "Guarde o token em local seguro e não o compartilhe com terceiros.\n\n"
        "Se você não reconhece esta solicitação, entre em contato com o suporte."
    )
    return (
        "<!doctype html><html><body style='font-family:Arial,sans-serif'>"
        f"<pre style='white-space:pre-wrap;font-size:14px;line-height:1.5'>"
        f"{html.escape(body)}"
        "</pre>"
        "</body></html>"
    )


def build_api_token_rejected_email_html(reason: str) -> str:
    reason_escaped = html.escape(reason or "")
    return f"""
<!doctype html>
<html>
  <body style="font-family:Arial,sans-serif;background:#0b1211;padding:24px;color:#eef2f1">
    <div style="max-width:520px;margin:0 auto;background:#0e1b19;border-radius:12px;padding:24px">
      <h2 style="margin:0 0 8px">Sua solicitação de token de API foi rejeitada.</h2>
      <div style="margin:14px 0 18px;padding:14px 16px;border-radius:12px;
                  background:#061816;border:1px solid rgba(255,255,255,.08);">
        <p style="margin:0 0 6px;font-size:13px;opacity:.85;">
          Motivo informado pelo administrador:
        </p>
        <p style="margin:0;font-size:14px;line-height:1.6;white-space:pre-wrap;">
          {reason_escaped}
        </p>
      </div>
      <p style="opacity:.8;margin:0">
        Se tiver dúvidas ou acreditar que isso ocorreu por engano, entre em contato com o suporte do Veracity.
      </p>
    </div>
  </body>
</html>
    """.strip()


def reactivate_account_email_html(name: str, code: str) -> str:
    return f"""
<!doctype html>
<html>
  <body style="font-family:Arial,sans-serif;background:#0b1211;padding:24px;color:#eef2f1">
    <div style="max-width:520px;margin:0 auto;background:#0e1b19;border-radius:12px;padding:24px">
      <h2 style="margin:0 0 8px">Reativar conta</h2>
      <p style="opacity:.9">Olá, <b>{html.escape(name or '')}</b>. Você solicitou a reativação da sua conta no Veracity.</p>
      <p style="opacity:.9">Para concluir, informe o código abaixo na plataforma.</p>
      <div style="margin:16px 0;padding:12px 0;text-align:center;font-size:24px;letter-spacing:6px;font-weight:700;background:#051513;border-radius:10px;">
        {html.escape(code)}
      </div>
      <p style="opacity:.8">O código é válido por poucos minutos. Se você não solicitou, ignore este e-mail.</p>
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
