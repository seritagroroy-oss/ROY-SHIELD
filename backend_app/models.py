from urllib.parse import urlparse

from pydantic import BaseModel, field_validator


class ScanRequest(BaseModel):
    url: str

    @field_validator("url")
    @classmethod
    def validate_url(cls, value: str) -> str:
        candidate = value.strip()
        if not candidate:
            raise ValueError("url_required")
        if len(candidate) > 2048 or " " in candidate:
            raise ValueError("url_invalid")
        parsed = urlparse(candidate if "://" in candidate else f"https://{candidate}")
        if not parsed.netloc:
            raise ValueError("url_invalid")
        return candidate


class ReportRequest(BaseModel):
    url: str
    report_type: str
    comment: str = ""
    score: int | None = None
    verdict: str | None = None
    level: str | None = None

    @field_validator("url")
    @classmethod
    def validate_report_url(cls, value: str) -> str:
        return ScanRequest.validate_url(value)

    @field_validator("report_type")
    @classmethod
    def validate_report_type(cls, value: str) -> str:
        allowed = {"phishing", "recrutement", "concours", "paiement", "usurpation", "autre"}
        candidate = value.strip().lower()
        if candidate not in allowed:
            raise ValueError("report_type_invalid")
        return candidate

    @field_validator("comment")
    @classmethod
    def validate_comment(cls, value: str) -> str:
        return value.strip()[:500]

    @field_validator("level")
    @classmethod
    def validate_level(cls, value: str | None) -> str | None:
        if value is None:
            return value
        candidate = value.strip().lower()
        if candidate not in {"safe", "warn", "danger"}:
            raise ValueError("level_invalid")
        return candidate


class ReportModerationRequest(BaseModel):
    status: str
    note: str = ""

    @field_validator("status")
    @classmethod
    def validate_status(cls, value: str) -> str:
        candidate = value.strip().lower()
        if candidate not in {"pending", "reviewed", "confirmed", "dismissed"}:
            raise ValueError("status_invalid")
        return candidate

    @field_validator("note")
    @classmethod
    def validate_note(cls, value: str) -> str:
        return value.strip()[:500]


class ShareReportRequest(BaseModel):
    url: str
    verdict: str
    level: str
    score: int
    signals: list[dict] = []

    @field_validator("url")
    @classmethod
    def validate_url(cls, value: str) -> str:
        return ScanRequest.validate_url(value)

    @field_validator("level")
    @classmethod
    def validate_level(cls, value: str) -> str:
        candidate = value.strip().lower()
        if candidate not in {"safe", "warn", "danger"}:
            raise ValueError("level_invalid")
        return candidate


class RegisterRequest(BaseModel):
    name: str
    email: str
    password: str

    @field_validator("name")
    @classmethod
    def validate_name(cls, value: str) -> str:
        candidate = value.strip()
        if len(candidate) < 2 or len(candidate) > 80:
            raise ValueError("name_invalid")
        return candidate

    @field_validator("email")
    @classmethod
    def validate_email(cls, value: str) -> str:
        candidate = value.strip().lower()
        if "@" not in candidate or len(candidate) > 254:
            raise ValueError("email_invalid")
        return candidate

    @field_validator("password")
    @classmethod
    def validate_password(cls, value: str) -> str:
        if len(value) < 8 or len(value) > 128:
            raise ValueError("password_invalid")
        return value


class LoginRequest(BaseModel):
    email: str
    password: str

    @field_validator("email")
    @classmethod
    def validate_login_email(cls, value: str) -> str:
        return RegisterRequest.validate_email(value)

    @field_validator("password")
    @classmethod
    def validate_login_password(cls, value: str) -> str:
        if not value or len(value) > 128:
            raise ValueError("password_invalid")
        return value
