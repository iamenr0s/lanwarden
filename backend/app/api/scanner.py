from fastapi import APIRouter, Depends, HTTPException, Request, status

from app.api.deps import require_user
from app.schemas.scanner import ScanRunsOut, ScanStarted

router = APIRouter(prefix="/api/scanner", tags=["scanner"], dependencies=[Depends(require_user)])


@router.post("/run", response_model=ScanStarted, status_code=status.HTTP_202_ACCEPTED)
def run_scan(request: Request):
    """Start a scan in the background; poll GET /api/scanner/runs for the result."""
    if not request.app.state.scanner.trigger_manual():
        raise HTTPException(status.HTTP_409_CONFLICT, "A scan is already running")
    return ScanStarted(started=True)


@router.get("/runs", response_model=ScanRunsOut)
def list_runs(request: Request):
    scanner = request.app.state.scanner
    return ScanRunsOut(running=scanner.running, runs=list(scanner.runs))
