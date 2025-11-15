from enum import Enum


class UserRole(str, Enum):
    user = "user"
    admin = "admin"


class UserStatus(str, Enum):
    active = "active"
    inactive = "inactive"


class AnalysisType(str, Enum):
    url = "url"
    image = "image"


class AnalysisStatus(str, Enum):
    pending = "pending"
    done = "done"
    error = "error"


class RiskLabel(str, Enum):
    fake = "fake"
    safe = "safe"
    suspicious = "suspicious"
    malicious = "malicious"
    unknown = "unknown"
