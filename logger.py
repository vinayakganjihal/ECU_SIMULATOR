# logger.py  (updated)
#
# Centralized logging system for the Virtual ECU Simulator.
#
# Changes from original:
#   - Session-based JSONL files: one folder per run, never a single growing file
#   - JSONL records EVERY event (DEBUG and above) — all CAN frames, all UDS
#     requests/responses, all vuln triggers, all failures. This guarantees
#     complete replay fidelity: even bugs triggered by normal traffic are captured.
#   - Auto-deletes oldest sessions when more than MAX_SESSIONS exist
#   - ecu_simulation.log still gets full detail (rotating by size, max 5MB x3)
#   - Writes a "current_session.txt" pointer so GUI always knows latest JSONL
#
# Outputs:
#   logs/ecu_simulation.log              — Full human-readable log (size-rotated)
#   logs/session_YYYY-MM-DD_HH-MM-SS/
#       session.jsonl                    — EVERY event for this session (for replay)
#       session.log                      — Full text log for this session
#   logs/current_session.txt             — Path to latest session JSONL (for GUI)
#
# Log levels:
#   DEBUG   → Internal details (CAN frames, state snapshots)
#   INFO    → Normal operations
#   WARNING → Vulnerability triggers, NRC responses
#   ERROR   → Failures, crashes

import logging
import logging.handlers
import os
import sys
import json
import glob
import shutil
import traceback
from datetime import datetime
from typing import Optional, Callable

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
LOG_DIR      = "logs"
MAX_SESSIONS = 10          # keep last 10 session folders, delete older ones
MAX_LOG_SIZE = 5 * 1024 * 1024   # 5 MB per text log file
MAX_LOG_BACKUPS = 3              # keep 3 rotated text log files

# Session timestamp (set once at startup)
_SESSION_TS   = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
# All paths relative to the logger file's own directory so the project
# is portable — works on any machine, any folder, without reconfiguration.
_BASE_DIR     = os.path.join(os.path.dirname(os.path.abspath(__file__)), LOG_DIR)
SESSION_DIR   = os.path.join(_BASE_DIR, f"session_{_SESSION_TS}")
SESSION_JSONL = os.path.join(SESSION_DIR, "session.jsonl")
SESSION_LOG   = os.path.join(SESSION_DIR, "session.log")
GLOBAL_LOG    = os.path.join(_BASE_DIR, "ecu_simulation.log")
CURRENT_PTR   = os.path.join(_BASE_DIR, "current_session.txt")

os.makedirs(_BASE_DIR,    exist_ok=True)
os.makedirs(SESSION_DIR,  exist_ok=True)

# Write absolute path derived from __file__ — portable across machines
# because it's always relative to logger.py's own location, not cwd
with open(CURRENT_PTR, "w") as _f:
    _f.write(SESSION_JSONL)


# ---------------------------------------------------------------------------
# Session cleanup — delete oldest when over MAX_SESSIONS
# ---------------------------------------------------------------------------
def _cleanup_old_sessions():
    pattern = os.path.join(LOG_DIR, "session_*")
    sessions = sorted(glob.glob(pattern))   # alphabetical = chronological
    while len(sessions) > MAX_SESSIONS:
        oldest = sessions.pop(0)
        try:
            shutil.rmtree(oldest)
        except Exception:
            pass

_cleanup_old_sessions()


# ---------------------------------------------------------------------------
# Human-readable text formatter
# ---------------------------------------------------------------------------
class _TextFormatter(logging.Formatter):
    _LEVEL = {
        "DEBUG":    "DBG",
        "INFO":     "INF",
        "WARNING":  "WRN",
        "ERROR":    "ERR",
        "CRITICAL": "CRT",
    }

    def format(self, record: logging.LogRecord) -> str:
        ts   = datetime.fromtimestamp(record.created).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        lvl  = self._LEVEL.get(record.levelname, record.levelname)
        loc  = f"{record.filename}:{record.funcName}:{record.lineno}"
        line = f"[{ts}] [{lvl}] [{record.name:<28}] [{loc}] {record.getMessage()}"
        if record.exc_info:
            line += "\n" + self.formatException(record.exc_info)
        return line


# ---------------------------------------------------------------------------
# JSONL handler — WARNING and above only (vulns + failures only)
# ---------------------------------------------------------------------------
class _JSONLHandler(logging.Handler):
    """
    Writes one JSON object per line — ALL levels recorded.
    Every CAN frame, every UDS request/response, every vuln trigger,
    every failure. This ensures complete replay fidelity: even a bug
    triggered by a normal frame can be reproduced exactly.
    Session-based files keep things clean without losing any data.
    Also adds a session_id field to every record.
    """

    def __init__(self, path: str):
        super().__init__(level=logging.DEBUG)   # ← ALL levels recorded
        self._fh = open(path, "a", encoding="utf-8")
        self._session_id = _SESSION_TS

    def emit(self, record: logging.LogRecord) -> None:
        try:
            entry: dict = {
                "session_id":  self._session_id,
                "timestamp":   datetime.fromtimestamp(record.created).isoformat(timespec="milliseconds"),
                "level":       record.levelname,
                "logger":      record.name,
                "module":      record.module,
                "function":    record.funcName,
                "line":        record.lineno,
                "message":     record.getMessage(),
            }
            # Attach structured payloads
            for key in ("ecu_context", "uds_payload", "vuln_info", "failure_info"):
                val = getattr(record, key, None)
                if val is not None:
                    entry[key] = val
            if record.exc_info:
                entry["exception"] = self.formatException(record.exc_info)

            self._fh.write(json.dumps(entry) + "\n")
            self._fh.flush()
        except Exception:
            self.handleError(record)

    def close(self) -> None:
        try:
            self._fh.close()
        except Exception:
            pass
        super().close()


# ---------------------------------------------------------------------------
# Root logger bootstrap  (called once at import time)
# ---------------------------------------------------------------------------
def _bootstrap() -> logging.Logger:
    root = logging.getLogger("ecu")
    if root.handlers:
        return root

    root.setLevel(logging.DEBUG)
    root.propagate = False

    # ── Console — INFO and above ─────────────────────────────────────────
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.INFO)
    ch.setFormatter(_TextFormatter())
    root.addHandler(ch)

    # ── Global rotating text log — full detail ───────────────────────────
    fh = logging.handlers.RotatingFileHandler(
        GLOBAL_LOG, maxBytes=MAX_LOG_SIZE,
        backupCount=MAX_LOG_BACKUPS, encoding="utf-8"
    )
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(_TextFormatter())
    root.addHandler(fh)

    # ── Session text log — full detail for this session ──────────────────
    sfh = logging.FileHandler(SESSION_LOG, encoding="utf-8")
    sfh.setLevel(logging.DEBUG)
    sfh.setFormatter(_TextFormatter())
    root.addHandler(sfh)

    # ── Session JSONL — WARNING+ only (vulns & failures) ─────────────────
    jh = _JSONLHandler(SESSION_JSONL)
    root.addHandler(jh)

    root.info(
        "=" * 72 + f"\n  ECU Simulation Session: {_SESSION_TS}\n" + "=" * 72
    )
    root.info(f"[SYSTEM] Session JSONL: {SESSION_JSONL}")
    root.info(f"[SYSTEM] Session log:   {SESSION_LOG}")
    return root


_ROOT = _bootstrap()


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(f"ecu.{name}")


# ---------------------------------------------------------------------------
# ECULogger — unchanged public API (drop-in replacement)
# ---------------------------------------------------------------------------
class ECULogger:
    """
    Structured logging helper. Drop-in replacement for original.
    All method signatures unchanged — no other files need editing.
    """

    SESSION_NAMES = {0x01: "DEFAULT", 0x02: "PROGRAMMING", 0x03: "EXTENDED"}

    def __init__(self, component: str, gui_callback: Optional[Callable[[str], None]] = None):
        self._logger    = get_logger(component)
        self._component = component
        self._gui_cb    = gui_callback

    def _gui(self, msg: str) -> None:
        if self._gui_cb:
            try:
                self._gui_cb(msg)
            except Exception:
                pass

    @staticmethod
    def _session_name(raw: int) -> str:
        return ECULogger.SESSION_NAMES.get(raw, f"0x{raw:02X}")

    def _record_extra(self, record: logging.LogRecord, **fields) -> logging.LogRecord:
        for k, v in fields.items():
            setattr(record, k, v)
        return record

    def debug(self, msg: str) -> None:
        self._logger.debug(msg, stacklevel=2)

    def info(self, msg: str) -> None:
        self._logger.info(msg, stacklevel=2)
        self._gui(msg)

    def warning(self, msg: str) -> None:
        self._logger.warning(msg, stacklevel=2)
        self._gui(f"[WARN] {msg}")

    def error(self, msg: str) -> None:
        self._logger.error(msg, stacklevel=2)
        self._gui(f"[ERR] {msg}")

    def log_state_snapshot(self, state, extra: str = "") -> None:
        sess = self._session_name(state.session)
        sec  = f"UNLOCKED(lvl={state.security_level})" if state.security_level > 0 else "LOCKED"
        msg  = (
            f"[STATE] Session={sess} Security={sec} "
            f"Faulted={state.faulted}({state.fault_reason or '-'}) "
            f"HangUntil={state.hang_until:.2f}"
        )
        if extra:
            msg += f" | {extra}"
        context = {
            "session":        sess,
            "session_raw":    state.session,
            "security_level": state.security_level,
            "faulted":        state.faulted,
            "fault_reason":   state.fault_reason,
            "auth_failures":  state.auth_failures_ram,
            "locked_until":   round(state.locked_until, 3),
            "hang_until":     round(state.hang_until, 3),
        }
        r = self._logger.makeRecord(
            self._logger.name, logging.DEBUG,
            __file__, 0, msg, [], None, "log_state_snapshot"
        )
        self._record_extra(r, ecu_context=context)
        self._logger.handle(r)

    def log_uds_request(self, payload: bytes, state=None) -> None:
        try:
            from uds_helpers import uds_sid_name
        except ImportError:
            def uds_sid_name(x): return f"SID(0x{x:02X})"

        sid      = payload[0] if payload else 0
        hex_pay  = payload.hex().upper()
        sid_name = uds_sid_name(sid)

        msg = (
            f"[RX] SID=0x{sid:02X}({sid_name}) "
            f"Payload={hex_pay} Len={len(payload)}"
        )
        if state:
            msg += (
                f" | PreState: Session={self._session_name(state.session)} "
                f"SecLvl={state.security_level} Faulted={state.faulted}"
            )

        context: dict = {}
        if state:
            context["pre_state"] = {
                "session":        self._session_name(state.session),
                "security_level": state.security_level,
                "faulted":        state.faulted,
            }

        r = self._logger.makeRecord(
            self._logger.name, logging.INFO,
            __file__, 0, msg, [], None, "log_uds_request"
        )
        self._record_extra(r,
            uds_payload={"hex": hex_pay, "sid": f"0x{sid:02X}",
                         "sid_name": sid_name, "length": len(payload),
                         "direction": "RX"},
            ecu_context=context or None,
        )
        self._logger.handle(r)
        self._gui(f"[RX][UDS] {hex_pay}")

    def log_uds_response(self, payload: bytes) -> None:
        try:
            from uds_helpers import nrc_name
        except ImportError:
            def nrc_name(x): return f"NRC(0x{x:02X})"

        hex_pay = payload.hex().upper()
        if payload[0] == 0x7F and len(payload) >= 3:
            nrc  = payload[2]
            msg  = f"[TX] NEGATIVE SID=0x{payload[1]:02X} NRC=0x{nrc:02X}({nrc_name(nrc)}) {hex_pay}"
            lvl  = logging.WARNING
        else:
            msg  = f"[TX] POSITIVE {hex_pay}"
            lvl  = logging.INFO

        r = self._logger.makeRecord(
            self._logger.name, lvl,
            __file__, 0, msg, [], None, "log_uds_response"
        )
        self._record_extra(r, uds_payload={"hex": hex_pay, "direction": "TX"})
        self._logger.handle(r)
        self._gui(f"[TX][UDS] {hex_pay}")

    def log_vulnerability(self, vuln: dict, payload: bytes, module: str = "") -> None:
        vid      = vuln.get("id", "UNKNOWN")
        name     = vuln.get("name", "Unnamed")
        effect   = vuln.get("effect", {})
        action   = effect.get("action", "NONE")
        log_msg  = effect.get("log_message", "")
        trigger  = vuln.get("trigger", {})
        hex_pay  = payload.hex().upper() if payload else ""
        mod      = module or self._component

        msg = (
            f"[VULN] {vid} '{name}' TRIGGERED | "
            f"Action={action} | Payload={hex_pay} | {log_msg}"
        )
        r = self._logger.makeRecord(
            self._logger.name, logging.WARNING,
            __file__, 0, msg, [], None, "log_vulnerability"
        )
        self._record_extra(r, vuln_info={
            "id":            vid,
            "name":          name,
            "action":        action,
            "trigger":       trigger,
            "log_message":   log_msg,
            "module":        mod,
            "input_payload": hex_pay,
            "reproduce":     f"Send payload hex: {hex_pay}",
        })
        self._logger.handle(r)
        self._gui(f"[VULN] {vid} {name} -> {action}")

    def log_failure(
        self,
        failure_type: str,
        description:  str,
        payload:      bytes = b"",
        exc_info=     None,
        state=        None,
    ) -> None:
        hex_pay = payload.hex().upper() if payload else ""
        state_snap: dict = {}
        if state:
            state_snap = {
                "session":        self._session_name(state.session),
                "security_level": state.security_level,
                "faulted":        state.faulted,
                "fault_reason":   state.fault_reason,
            }

        reproduce_steps = []
        if state:
            sess = self._session_name(state.session)
            if sess != "DEFAULT":
                reproduce_steps.append(f"1. Enter {sess} session (0x10 sub={state.session:02X})")
            if state.security_level > 0:
                reproduce_steps.append(f"2. Unlock security level {state.security_level}")
        if hex_pay:
            reproduce_steps.append(f"{len(reproduce_steps)+1}. Send payload: cansend vcan0 7E0#{hex_pay}")
        if not reproduce_steps:
            reproduce_steps = ["See payload and state in this log entry"]

        msg = (
            f"[FAILURE] Type={failure_type} | {description} | "
            f"Payload={hex_pay}"
        )
        r = self._logger.makeRecord(
            self._logger.name, logging.ERROR,
            __file__, 0, msg, [], exc_info, "log_failure"
        )
        self._record_extra(r, failure_info={
            "failure_type":    failure_type,
            "description":     description,
            "input_payload":   hex_pay,
            "ecu_state":       state_snap,
            "reproduce_steps": reproduce_steps,
        })
        self._logger.handle(r)
        self._gui(f"[FAILURE] {failure_type}: {description}")

    def log_exception(
        self,
        description: str,
        exc:         Exception,
        payload:     bytes = b"",
        state=       None,
    ) -> None:
        self.log_failure(
            failure_type="EXCEPTION",
            description=f"{description} — {type(exc).__name__}: {exc}",
            payload=payload,
            exc_info=sys.exc_info(),
            state=state,
        )
