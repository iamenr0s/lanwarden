from datetime import datetime

from pydantic import BaseModel


class ProviderRunOut(BaseModel):
    name: str
    observations: int
    error: str | None


class ScanRunOut(BaseModel):
    id: int
    trigger: str
    started_at: datetime
    finished_at: datetime | None
    providers: list[ProviderRunOut]
    summary: dict[str, int] | None
    error: str | None


class ScanRunsOut(BaseModel):
    running: bool
    runs: list[ScanRunOut]


class ScanStarted(BaseModel):
    started: bool
