from app.utils.constants import URL_EXAMPLE, MAX_URL_LENGTH

ERROR_MESSAGE_INVALID_PROTOCOL = f"A URL deve incluir o protocolo http:// ou https://. Exemplo: {URL_EXAMPLE}"
ERROR_MESSAGE_INVALID_DOMAIN = f"A URL deve conter um domínio válido. Exemplo: {URL_EXAMPLE}"
ERROR_MESSAGE_EMPTY_URL = "A URL não pode estar vazia."
ERROR_MESSAGE_INVALID_URL = f"A URL informada não é válida. Certifique-se de utilizar o formato completo. Exemplo: {URL_EXAMPLE}"
ERROR_MESSAGE_MAX_LENGTH = f"A URL excede o limite de {MAX_URL_LENGTH} caracteres."
ERROR_MESSAGE_INVALID_CHARACTERS = "A URL fornecida contém caracteres não permitidos."
