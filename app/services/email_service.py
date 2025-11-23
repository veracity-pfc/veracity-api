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
      <h2 style="margin:0 0 8px; color: #ffffff;">Confirme seu e-mail</h2>
      <p style="opacity:.9; color: #ffffff;">Olá, <b>{name}</b>. Confirme seu endereço de e-mail informando o código abaixo na plataforma Veracity.
      </br>Ele expira em <b>10 minutos</b>.</p>
      <div style="letter-spacing:.5rem;font-size:28px;font-weight:700;background:#0f2c27;
                  padding:14px 18px;border-radius:10px;display:inline-block;margin:12px 0; color: #ffffff;">
        {code_fmt}
      </div>
      <p style="opacity:.8; color: #ffffff;">Se você não solicitou este código, pode ignorar esta mensagem com segurança.</br>Por favor, não compartilhe este código com ninguém.</p>
    </div>
  </body>
</html>
    """.strip()


def build_api_token_approved_email_html(expires_at) -> str:
    expires_fmt = expires_at.strftime("%d/%m/%Y às %H:%M")
    return f"""
<!doctype html>
<html>
  <body style="font-family:Arial,sans-serif;background:#0b1211;padding:24px;color:#eef2f1">
    <div style="max-width:520px;margin:0 auto;background:#0e1b19;border-radius:12px;padding:24px">
      <h2 style="margin:0 0 8px; color: #ffffff;">Token de API gerado com sucesso</h2>
      <p style="opacity:.9; color: #ffffff;">
        Seu token foi criado com sucesso e já pode ser utilizado para acessar os endpoints do Veracity via API.
      </p>
      <p style="opacity:.9; color: #ffffff;">Data de expiração: <b>{expires_fmt}</b></p>
      <p style="opacity:.8; color: #ffffff;">
        Para visualizar o token completo e copiá-lo, acesse a sua conta no Veracity e utilize a tela de perfil.
        O token será exibido de forma completa apenas uma vez.
      </p>
    </div>
  </body>
</html>
    """.strip()


def build_api_token_rejected_email_html(reason: str) -> str:
    reason_escaped = html.escape(reason or "")
    return f"""
<!doctype html>
<html>
  <body style="font-family:Arial,sans-serif;background:#0b1211;padding:24px;color:#eef2f1">
    <div style="max-width:520px;margin:0 auto;background:#0e1b19;border-radius:12px;padding:24px">
      <h2 style="margin:0 0 8px; color: #ffffff;">Sua solicitação de token de API foi rejeitada.</h2>
      <div style="margin:14px 0 18px;padding:14px 16px;border-radius:12px;
                  background:#061816;border:1px solid rgba(255,255,255,.08);">
        <p style="margin:0 0 6px;font-size:13px;opacity:.85; color: #ffffff;">
          Motivo informado pelo administrador:
        </p>
        <p style="margin:0;font-size:14px;line-height:1.6;white-space:pre-wrap; color: #ffffff;">
          {reason_escaped}
        </p>
      </div>
      <p style="opacity:.8;margin:0; color: #ffffff;">
        Se tiver dúvidas ou acreditar que isso ocorreu por engano, entre em contato com o suporte do Veracity.
      </p>
    </div>
  </body>
</html>
    """.strip()


def build_api_token_expired_email_html(expires_at) -> str:
    expires_fmt = expires_at.strftime("%d/%m/%Y às %H:%M")
    return f"""
<!doctype html>
<html>
  <body style="font-family:Arial,sans-serif;background:#0b1211;padding:24px;color:#eef2f1">
    <div style="max-width:520px;margin:0 auto;background:#0e1b19;border-radius:12px;padding:24px">
      <h2 style="margin:0 0 8px">Seu token de API expirou</h2>
      <p style="opacity:.9; color: #ffffff;">
        O token de API associado à sua conta atingiu a data de expiração em <b>{expires_fmt}</b> e não pode mais ser utilizado.
      </p>
      <p style="opacity:.8; color: #ffffff;">
        Caso ainda precise de acesso via API, solicite um novo token pela plataforma Veracity.
      </p>
    </div>
  </body>
</html>
    """.strip()


def build_api_token_revoked_email_html(expires_at, reason: str | None) -> str:
    expires_fmt = expires_at.strftime("%d/%m/%Y às %H:%M")
    reason_text = html.escape(reason or "Motivo não informado.")
    return f"""
<!doctype html>
<html>
  <body style="font-family:Arial,sans-serif;background:#0b1211;padding:24px;color:#eef2f1">
    <div style="max-width:520px;margin:0 auto;background:#0e1b19;border-radius:12px;padding:24px">
      <h2 style="margin:0 0 8px">Seu token de API foi revogado</h2>
      <p style="opacity:.9; color: #ffffff;">
        O token de API associado à sua conta foi revogado e não pode mais ser utilizado.
      </p>
      <p style="opacity:.9; color: #ffffff;">Data de expiração original: <b>{expires_fmt}</b></p>
      <div style="margin:14px 0 18px;padding:14px 16px;border-radius:12px;
                  background:#061816;border:1px solid rgba{chr(40)}255,255,255,.08{chr(41)};">
        <p style="margin:0 0 6px;font-size:13px;opacity:.85; color: #ffffff;">
          Motivo informado:
        </p>
        <p style="margin:0;font-size:14px;line-height:1.6;white-space:pre-wrap; color: #ffffff;">
          {reason_text}
        </p>
      </div>
      <p style="opacity:.8;margin:0; color: #ffffff;">
        Se precisar de um novo token, solicite novamente pela plataforma Veracity.
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
      <p style="opacity:.9; color: #ffffff;">Olá, <b>{html.escape(name or '')}</b>. Você solicitou a reativação da sua conta no Veracity.</p>
      <p style="opacity:.9; color: #ffffff;">Para concluir, informe o código abaixo na plataforma.</p>
      <div style="margin:16px 0;padding:12px 0;text-align:center;font-size:24px;letter-spacing:6px;font-weight:700;background:#051513;border-radius:10px;">
        {html.escape(code)}
      </div>
      <p style="opacity:.8; color: #ffffff;">O código é válido por poucos minutos. Se você não solicitou, ignore este e-mail.</p>
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
      <p style="opacity:.9; color: #ffffff;">Olá, <b>{name}</b>. Você solicitou a redefinição da sua senha no Veracity.</p>
      <p style="opacity:.9; color: #ffffff;">Clique no botão abaixo para criar uma nova senha. O link expira em <b>30 minutos</b>.</p>
      <p><a href="{link}" style="display:inline-block;background:#1c6a58;color:#fff;padding:12px 18px;border-radius:10px;text-decoration:none;font-weight:700">Redefinir senha</a></p>
      <p style="opacity:.8; color: #ffffff;">Se você não solicitou, ignore este e-mail.</p>
    </div>
  </body>
</html>
    """.strip()


def build_contact_reply_email_html(subject: str, original_message: str, reply: str) -> str:
    clean_subject = subject.replace("Nova mensagem recebida - ", "")
    clean_subject = html.escape(clean_subject)

    limit = 300
    escaped_original = html.escape(original_message or "")
    if len(escaped_original) > limit:
        display_original = f"{escaped_original[:limit].strip()}..."
    else:
        display_original = escaped_original

    escaped_reply = html.escape(reply)

    return f"""
<!doctype html>
<html>
  <head>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
  </head>
  <body style="font-family: 'Segoe UI', Arial, sans-serif; background-color: #0b1211; margin: 0; padding: 0; color: #eef2f1;">
    
    <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0">
      <tr>
        <td style="padding: 24px 12px;" align="center">
          
          <div style="max-width: 600px; margin: 0 auto; background-color: #0e1b19; border-radius: 12px; border: 1px solid rgba(255,255,255,0.08); overflow: hidden;">
            
            <div style="padding: 32px 24px; border-bottom: 1px solid rgba(255,255,255,0.05);">
              <h2 style="margin: 0 0 8px; font-size: 20px; color: #ffffff;">Retorno sobre sua {clean_subject}</h2>
              <p style="margin: 0; font-size: 14px; opacity: 0.8; line-height: 1.5; color: #ffffff;">
                Olá. Analisamos sua mensagem e trouxemos um retorno.
              </p>
            </div>

            <div style="padding: 24px;">
              
              <div style="margin-bottom: 24px;">
                <p style="margin: 0 0 8px; font-size: 12px; text-transform: uppercase; letter-spacing: 1px; font-weight: bold; color: #4cd6a3;">
                  Nossa Resposta
                </p>
                <div style="background-color: rgba(28, 106, 88, 0.15); border-left: 4px solid #1c6a58; padding: 16px; border-radius: 4px;">
                  <p style="margin: 0; font-size: 15px; line-height: 1.6; white-space: pre-wrap; color: #eef2f1;">{escaped_reply}</p>
                </div>
              </div>

              <div style="margin-top: 32px; padding-top: 20px; border-top: 1px solid rgba(255,255,255,0.1);">
                <p style="margin: 0 0 8px; font-size: 12px; opacity: 0.6; color: #ffffff;">
                  Você escreveu anteriormente:
                </p>
                <div style="font-style: italic; opacity: 0.7; font-size: 13px; line-height: 1.5; padding-left: 12px; border-left: 2px solid #333; color: #ffffff;">
                  "{display_original}"
                </div>
              </div>

            </div>

            <div style="background-color: #080f0e; padding: 16px 24px; text-align: center;">
              <p style="margin: 0; font-size: 12px; opacity: 0.5; color: #ffffff;">
                Atenciosamente,<br>Equipe Veracity
              </p>
            </div>

          </div>
        </td>
      </tr>
    </table>

  </body>
</html>
    """.strip()