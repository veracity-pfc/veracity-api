from types import SimpleNamespace
from datetime import datetime
from sqlalchemy import select
from app.services.auth_service import AuthService
from app.domain.user_model import User
from app.domain.enums import UserStatus, UserRole
from app.core.security import hash_password
from datetime import datetime, timezone

class FakeResult:
    def __init__(self, obj): self._obj = obj
    def scalar_one_or_none(self): return self._obj

class FakeSession:
    def __init__(self, user):
        self.user = user
        self.logged_execs = []
    async def execute(self, stmt):
        self.logged_execs.append(stmt)
        if isinstance(stmt, type(select(User))):
            return FakeResult(self.user)
        return FakeResult(None)
    async def commit(self): pass
    async def flush(self): pass

class FakeRequest:
    client = SimpleNamespace(host="1.2.3.4")
    headers = {}

async def test_login_success():
    user = User(
        id="00000000-0000-0000-0000-000000000001",
        name="Manu",
        email="m@x.com",
        password_hash=hash_password("Str0ng!Pass"),
        role=UserRole.user,
        status=UserStatus.active,
        accepted_terms_at=datetime.now(timezone.utc),
    )
    session = FakeSession(user)
    svc = AuthService(session)
    token = await svc.login("m@x.com", "Str0ng!Pass", FakeRequest())
    assert isinstance(token, str) and len(token) > 10
