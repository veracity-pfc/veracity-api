from typing import Literal
from pydantic import BaseModel

class OkOut(BaseModel):
    ok: Literal[True] = True

class QuotaOut(BaseModel):
    scope: str              
    limit: int
    used_today: int
    remaining_today: int