from __future__ import annotations

import os
from contextlib import asynccontextmanager

from bcrypt import checkpw, hashpw, gensalt
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.core.database import engine
from app.core.security import pwd_context
from app.api.controllers import (
    admin_controller,
    analysis_controller,
    auth_controller,
    contact_controller,
    user_controller,
    history_controller,
    api_token_controller
)

import logging
import sys

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)

logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)

logging.getLogger("httpx").propagate = False
logging.getLogger("httpcore").propagate = False


@asynccontextmanager
async def lifespan(app: FastAPI):
    try:
        hashed = pwd_context.hash("warmup@123!")
        pwd_context.verify("warmup@123!", hashed)
        checkpw(b"warmup", hashpw(b"warmup", gensalt()))
    except Exception:
        pass

    yield

    try:
        await engine.dispose()
    except Exception:
        pass


app = FastAPI(
    title="Veracity API",
    version="1.0",
    debug=False,
    lifespan=lifespan,
)

_env_origins = os.getenv(
    "ALLOWED_ORIGINS",
    "http://localhost:5173,http://127.0.0.1:5173",
)
ALLOWED_ORIGINS = [origin.strip() for origin in _env_origins.split(",") if origin.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "Accept", "Access-Control-Allow-Origin"],
    expose_headers=["Content-Disposition"],
)


@app.exception_handler(StarletteHTTPException)
async def http_ex_handler(_: Request, exc: StarletteHTTPException) -> JSONResponse:
    return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})


@app.exception_handler(RequestValidationError)
async def validation_ex_handler(request: Request, exc: RequestValidationError):
    errors = exc.errors()
    messages = []

    for e in errors:
        if isinstance(e, dict):
            msg = e.get("msg")
            if msg:
                messages.append(str(msg))

    if not messages:
        detail = "Erro de validação"
    else:
        detail = " | ".join(messages)

    return JSONResponse(
        status_code=422,
        content={
            "detail": detail,
            "errors": errors,
        },
    )


@app.exception_handler(Exception)
async def unhandled_ex_handler(_: Request, __: Exception) -> JSONResponse:
    return JSONResponse(status_code=500, content={"detail": "Internal Server Error"})


app.include_router(auth_controller.router)
app.include_router(user_controller.router)
app.include_router(admin_controller.router)
app.include_router(contact_controller.router)
app.include_router(analysis_controller.router)
app.include_router(history_controller.router)
app.include_router(api_token_controller.router)


@app.get("/health")
def health() -> dict[str, bool]:
    return {"ok": True}


@app.get("/ready")
def ready() -> dict[str, str | bool]:
    return {"db": True, "app": "ready"}
