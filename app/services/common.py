from __future__ import annotations

from typing import Optional


def resolve_user_id(request, explicit_user_id: Optional[str]) -> Optional[str]:
    if explicit_user_id:
        return explicit_user_id
    try:
        state = getattr(request, "state", None)
        candidate = None
        if state is not None:
            user = getattr(state, "user", None)
            if hasattr(user, "id") and user.id:
                candidate = user.id
            if not candidate:
                candidate = getattr(state, "user_id", None)
        if not candidate:
            user2 = getattr(request, "user", None)
            if hasattr(user2, "id") and user2.id:
                candidate = user2.id
            elif isinstance(user2, str) and user2:
                candidate = user2
        if candidate:
            return str(candidate)
    except Exception:
        return None
    return None