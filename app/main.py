from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from contextlib import asynccontextmanager
from sqlalchemy import text
import asyncio
from .database import engine
from .routers import auth, users, admin, analysis
from .security import pwd_context  
from bcrypt import checkpw, hashpw, gensalt 

@asynccontextmanager
async def lifespan(app: FastAPI):
    try:
        async with engine.begin() as conn:
            await conn.execute(text("SELECT 1"))
        async with engine.begin() as conn:
            await conn.execute(text("SELECT 1 FROM users LIMIT 1"))
        _h = pwd_context.hash("warmup@123!")
        pwd_context.verify("warmup@123!", _h)
        checkpw(b"warmup", hashpw(b"warmup", gensalt()))
    except Exception:
        pass

    keep_running = True

    async def keepalive():
        while keep_running:
            try:
                async with engine.begin() as conn:
                    await conn.execute(text("SELECT 1"))
            except Exception:
                pass
            await asyncio.sleep(300)  

    task = asyncio.create_task(keepalive())

    yield  

    keep_running = False
    task.cancel()
    try:
        await engine.dispose()
    except Exception:
        pass

app = FastAPI(title="Veracity API", version="1.0", debug=False, lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.exception_handler(Exception)
async def unhandled_ex_handler(_: Request, __: Exception):
    return JSONResponse(status_code=500, content={"detail": "Internal Server Error"})

app.include_router(auth.router)
app.include_router(users.router)
app.include_router(admin.router)
app.include_router(analysis.router)

@app.get("/health")
def health():
    return {"ok": True}
