from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from app.routers import analysis_router
from app.utils.error_message import ERROR_MESSAGE_INVALID_URL

app = FastAPI(title="Veracity API", version="1.0.0")

app.include_router(analysis_router.router)

@app.exception_handler(RequestValidationError)
async def bad_request_response(req: Request, validation_error: RequestValidationError):
    error_details = validation_error.errors()
    message = error_details[0].get("msg", ERROR_MESSAGE_INVALID_URL)

    return JSONResponse(
        status_code=400,
        content={"detail": message}
    )
