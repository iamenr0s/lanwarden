import logging
import threading
import time
from collections import deque
from collections.abc import Callable

from sqlalchemy import func, select
from sqlalchemy.orm import Session, sessionmaker

from app.db.types import utcnow
from app.discovery.base import DiscoveryProvider, ProviderResult, ScanContext
from app.integrations.adguard import AdGuardError
from app.models.event import Event
from app.services.adguard_config import runtime_config
from app.services.crypto import SecretBox
from app.services.inventory import process_scan
from app.services.netinfo import DetectedNetwork, detect_networks
from app.services.settings import load_settings

log = logging.getLogger("lanwarden.scanner")
FIRST_SCAN_DELAY_S = 10
HISTORY = 20


class Scanner:
    """Runs discovery providers, feeds the inventory engine, keeps the last few run reports.

    shortcut: run history is in memory (lost on restart); events/sessions are the durable record.
    """

    def __init__(
        self,
        session_factory: sessionmaker[Session],
        providers: list[DiscoveryProvider],
        box: SecretBox,
        detect: Callable[[], list[DetectedNetwork]] = detect_networks,
        notify: Callable[[int], None] | None = None,
    ):
        self._sf = session_factory
        self.providers = providers
        self._box = box
        self._notify = notify  # called with the id of the last event that existed before the scan
        self._detect = detect
        self._lock = threading.Lock()  # one scan at a time
        self._wake = threading.Event()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._next_id = 1
        self.runs: deque[dict] = deque(maxlen=HISTORY)

    @property
    def running(self) -> bool:
        return self._lock.locked()

    # -- one scan --------------------------------------------------------------------------
    def run_once(self, trigger: str) -> dict | None:
        """Returns the run report, or None if a scan is already in progress."""
        if not self._lock.acquire(blocking=False):
            return None
        run = {"id": self._next_id, "trigger": trigger, "started_at": utcnow(), "finished_at": None,
               "providers": [], "summary": None, "error": None}
        self._next_id += 1
        self.runs.appendleft(run)
        since_event_id = 0
        try:
            with self._sf() as db:
                since_event_id = db.scalar(select(func.max(Event.id))) or 0
                scanner = load_settings(db).scanner
                adguard, problem = None, None
                if scanner.adguard_discovery_enabled:
                    try:
                        adguard = runtime_config(db, self._box)
                    except AdGuardError as e:
                        problem = e.message
                ctx = ScanContext(scanner, self._detect(), adguard, problem)
                observations, ok = [], False
                for provider in self.providers:
                    if not provider.enabled(scanner):
                        continue
                    try:
                        result = provider.scan(ctx)
                    except Exception:  # a buggy provider must not stop the others
                        log.exception("provider %s crashed", provider.name)
                        result = ProviderResult(error="unexpected error (see server log)")
                    run["providers"].append(
                        {"name": provider.name, "observations": len(result.observations), "error": result.error}
                    )
                    if result.error is None:
                        ok = ok or provider.gives_evidence
                        observations += result.observations
                if not run["providers"]:
                    run["error"] = "No discovery providers are enabled"
                elif not ok:
                    run["error"] = "All discovery providers failed; device presence was not updated"
                summary = process_scan(db, observations, ok, scanner, utcnow())
                db.commit()
                run["summary"] = vars(summary)
        except Exception:
            log.exception("scan failed")
            run["error"] = "Scan failed (see server log)"
        else:
            if self._notify:
                try:  # after the commit, so a slow or broken notifier can never lose scan results
                    self._notify(since_event_id)
                except Exception:
                    log.exception("notification dispatch failed")
        finally:
            run["finished_at"] = utcnow()
            self._lock.release()
        return run

    def trigger_manual(self) -> bool:
        if self.running:
            return False
        threading.Thread(target=self.run_once, args=("manual",), daemon=True, name="manual-scan").start()
        return True

    # -- schedule --------------------------------------------------------------------------
    def _interval(self) -> int:
        with self._sf() as db:
            return load_settings(db).scanner.scan_interval_seconds

    def _loop(self) -> None:
        due = time.monotonic() + FIRST_SCAN_DELAY_S
        while not self._stop.is_set():
            if self._wake.wait(max(0.0, due - time.monotonic())):  # woken: stop or interval changed
                self._wake.clear()
                if self._stop.is_set():
                    break
                due = time.monotonic() + self._interval()
                continue
            self.run_once("schedule")
            due = time.monotonic() + self._interval()

    def start(self) -> None:
        self._thread = threading.Thread(target=self._loop, daemon=True, name="scan-scheduler")
        self._thread.start()

    def reschedule(self) -> None:
        self._wake.set()

    def stop(self) -> None:
        self._stop.set()
        self._wake.set()
        if self._thread:
            self._thread.join(timeout=5)
