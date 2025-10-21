from typing import Literal
from pydantic import BaseModel

class OkOut(BaseModel):
    ok: Literal[True] = True
