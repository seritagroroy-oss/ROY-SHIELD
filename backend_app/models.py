from pydantic import BaseModel


class ScanRequest(BaseModel):
    url: str


class ReportRequest(BaseModel):
    url: str
    report_type: str
    comment: str = ""
    score: int | None = None
    verdict: str | None = None
    level: str | None = None
