from __future__ import annotations

import os
import asyncio
from contextlib import asynccontextmanager

from bcrypt import checkpw, hashpw, gensalt
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException
from sqlalchemy import text

from app.core.database import engine
from app.core.security import pwd_context
from app.api.controllers import (
    admin_controller,
    analysis_controller,
    auth_controller,
    contact_controller,
    users_controller,
    history_controller,
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    try:
        async with engine.begin() as conn:
            await conn.execute(text("SELECT 1"))
            await conn.execute(text("SELECT 1 FROM users LIMIT 1"))

        hashed = pwd_context.hash("warmup@123!")
        pwd_context.verify("warmup@123!", hashed)
        checkpw(b"warmup", hashpw(b"warmup", gensalt()))
    except Exception:
        pass

    async def keepalive():
        while True:
            try:
                async with engine.begin() as conn:
                    await conn.execute(text("SELECT 1"))
            except Exception:
                pass
            await asyncio.sleep(300)

    task = asyncio.create_task(keepalive())

    yield

    try:
        task.cancel()
    except Exception:
        pass

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
    allow_headers=["Authorization", "Content-Type", "Accept"],
    expose_headers=["Content-Disposition"],
)


@app.exception_handler(StarletteHTTPException)
async def http_ex_handler(_: Request, exc: StarletteHTTPException) -> JSONResponse:
    return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})


@app.exception_handler(RequestValidationError)
async def validation_ex_handler(_: Request, exc: RequestValidationError) -> JSONResponse:
    return JSONResponse(
        status_code=422,
        content={"detail": "Validation error", "errors": exc.errors()},
    )


@app.exception_handler(Exception)
async def unhandled_ex_handler(_: Request, __: Exception) -> JSONResponse:
    return JSONResponse(status_code=500, content={"detail": "Internal Server Error"})


app.include_router(auth_controller.router)
app.include_router(users_controller.router)
app.include_router(admin_controller.router)
app.include_router(contact_controller.router)
app.include_router(analysis_controller.router)
app.include_router(history_controller.router)


@app.get("/health")
def health() -> dict[str, bool]:
    return {"ok": True}


@app.get("/ready")
def ready() -> dict[str, str | bool]:
    return {"db": True, "app": "ready"}
