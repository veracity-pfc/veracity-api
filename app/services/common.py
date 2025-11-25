from __future__ import annotations

import logging
from typing import Optional

logger = logging.getLogger("veracity.common_service")


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
    except Exception as e:
        logger.debug(f"Failed to resolve user ID from request: {str(e)}")
        return None
    return None