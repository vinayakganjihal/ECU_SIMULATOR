# json_manager.py  —  Unified JSON Management System for ECU Simulator
# ─────────────────────────────────────────────────────────────────────
#
# OVERVIEW
# --------
# JSONManager is the single entry point for loading/unloading ALL JSON
# configuration files in the ECU Simulator.  The GUI presents only two
# buttons: "Load JSON" and "Unload JSON".  No type labels, no sub-menus.
#
# LOADING FLOW
# ─────────────
# 1. User clicks "Load JSON" → file dialog opens.
# 2. JSONManager.load_file(path) is called.
# 3. File is read and parsed (validation happens here — malformed JSON is
#    rejected with a descriptive error before anything else runs).
# 4. AUTO-DETECTION: each registered JSONHandler is tried in order via
#    its can_handle(data) method.  The first handler that returns True
#    "claims" the file.
# 5. The winning handler's load() is called — it applies the data to
#    whatever simulator subsystem it owns (e.g. VulnerabilityConfig).
# 6. A record is stored in the internal registry so the file appears in
#    the "Unload" dialog.
#
# UNLOADING FLOW
# ─────────────
# 1. User clicks "Unload JSON" → dialog lists every currently loaded file.
# 2. User selects one or more files and confirms.
# 3. JSONManager.unload_file(path) is called for each selected file.
# 4. The handler associated with that file clears its simulator state.
# 5. The record is removed from the registry.
#
# EXTENDING
# ─────────
# To support a new JSON type, subclass JSONHandler, implement can_handle()
# and load()/unload(), then call json_manager.register_handler(MyHandler())
# at startup.  Zero GUI changes required.
#
# ─────────────────────────────────────────────────────────────────────

import json
import os
from typing import Callable, Dict, List, Optional, Tuple


# ══════════════════════════════════════════════════════════════════════
# Abstract handler base
# ══════════════════════════════════════════════════════════════════════

class JSONHandler:
    """
    Base class for all JSON type handlers.

    Every concrete handler must implement:
      • TYPE_ID   — short string identifier shown in the status area
      • can_handle(data)  — True if this handler owns the given JSON structure
      • load(data, path, log, oracle)  — apply data; return (bool, message)
      • unload(log, oracle)  — clear state; return (bool, message)
      • summary()  — one-line description of what is currently loaded
    """

    #: Short identifier string used in log messages and the status panel.
    TYPE_ID: str = "generic"

    def can_handle(self, data: dict) -> bool:
        """Return True if this handler recognises and owns the JSON structure."""
        raise NotImplementedError

    def load(
        self,
        data: dict,
        path: str,
        log: Callable[[str], None],
        oracle: Callable[[str], None],
    ) -> Tuple[bool, str]:
        """
        Parse *data* and apply it to the relevant simulator subsystem.

        Returns
        -------
        (True,  success_message)  — file was applied successfully
        (False, error_message)    — something went wrong; no state was changed
        """
        raise NotImplementedError

    def unload(
        self,
        log: Callable[[str], None],
        oracle: Callable[[str], None],
    ) -> Tuple[bool, str]:
        """
        Clear all simulator state associated with this handler.

        Returns
        -------
        (True,  success_message)
        (False, error_message)
        """
        raise NotImplementedError

    def summary(self) -> str:
        """Return a one-line human-readable summary of currently loaded data."""
        return "—"


# ══════════════════════════════════════════════════════════════════════
# Vulnerability JSON handler
# ══════════════════════════════════════════════════════════════════════

class VulnerabilityHandler(JSONHandler):
    """
    Handles vulnerability configuration files.

    Recognition:  JSON root must contain both 'ecu_profile' (str) and
                  'vulnerabilities' (list).

    Internally delegates to the existing VulnerabilityConfig / VulnerabilityEngine
    pair already present in the simulator.  No duplication of loading logic.
    """

    TYPE_ID = "vulnerability"

    def __init__(self, cfg, engine_factory: Callable[[], None]):
        """
        Parameters
        ----------
        cfg             : VulnerabilityConfig instance owned by VirtualECU
        engine_factory  : zero-arg callable that rebuilds VulnerabilityEngine
                          (called after every load AND after unload so the
                          engine always reflects current cfg state)
        """
        self._cfg            = cfg
        self._engine_factory = engine_factory
        self._is_loaded      = False

    # ── Detection ─────────────────────────────────────────────────────
    def can_handle(self, data: dict) -> bool:
        return (
            isinstance(data.get("vulnerabilities"), list)
            and "ecu_profile" in data
        )

    # ── Load ──────────────────────────────────────────────────────────
    def load(self, data: dict, path: str, log, oracle) -> Tuple[bool, str]:
        # Point the existing VulnerabilityConfig at the chosen file and load.
        # VulnerabilityConfig.load() handles parsing, oracle messages, etc.
        self._cfg.path = path
        ok = self._cfg.load()
        if not ok:
            return False, f"Failed to parse vulnerability data in {os.path.basename(path)}"

        # Rebuild the engine so new rules take effect immediately.
        self._engine_factory()
        self._is_loaded = True
        n = len(self._cfg.vulnerabilities)
        enabled = sum(1 for v in self._cfg.vulnerabilities if v.get("enabled"))
        return (
            True,
            f"Vulnerability profile '{self._cfg.profile}' — "
            f"{n} rules ({enabled} enabled)",
        )

    # ── Unload ────────────────────────────────────────────────────────
    def unload(self, log, oracle) -> Tuple[bool, str]:
        if not self._is_loaded and not self._cfg.vulnerabilities:
            return False, "No vulnerability data is currently loaded"
        n       = len(self._cfg.vulnerabilities)
        profile = self._cfg.profile
        # VulnerabilityConfig.unload() resets all fields and emits log lines.
        self._cfg.unload()
        # Rebuild engine (now empty) so the simulator runs without rules.
        self._engine_factory()
        self._is_loaded = False
        return True, f"Removed {n} vulnerability rules (profile: {profile})"

    # ── Summary ───────────────────────────────────────────────────────
    def summary(self) -> str:
        if self._is_loaded or self._cfg.vulnerabilities:
            n = len(self._cfg.vulnerabilities)
            return f"Vulnerability · {self._cfg.profile} · {n} rule(s)"
        return "—"


# ══════════════════════════════════════════════════════════════════════
# Seed-pattern JSON handler
# ══════════════════════════════════════════════════════════════════════

class PatternHandler(JSONHandler):
    """
    Handles seed-pattern analysis files (PAT-NNN_*.json).

    Recognition:  JSON root contains 'seeds' or 'seeds_hex', AND either
                  the 'id' field starts with 'PAT-' or the 'name' field
                  contains the word 'seed' (case-insensitive).

    Multiple pattern files may be loaded simultaneously; each is stored
    independently under its pattern id.
    """

    TYPE_ID = "pattern"

    def __init__(self):
        # pat_id → full data dict
        self._patterns: Dict[str, dict] = {}
        # pat_id → originating file path (for unload-one)
        self._pat_path: Dict[str, str]  = {}

    # ── Detection ─────────────────────────────────────────────────────
    def can_handle(self, data: dict) -> bool:
        has_seeds = "seeds" in data or "seeds_hex" in data
        pat_id    = str(data.get("id",   ""))
        name      = str(data.get("name", "")).lower()
        return has_seeds and (pat_id.upper().startswith("PAT-") or "seed" in name)

    # ── Load ──────────────────────────────────────────────────────────
    def load(self, data: dict, path: str, log, oracle) -> Tuple[bool, str]:
        pat_id      = data.get("id",   os.path.splitext(os.path.basename(path))[0])
        name        = data.get("name", pat_id)
        seeds       = data.get("seeds", [])
        entropy     = data.get("expected_entropy", "?")
        prediction  = data.get("expected_predictor_result", "?")

        self._patterns[pat_id] = data
        self._pat_path[pat_id]  = path

        msg = (
            f"Pattern '{name}' · {len(seeds)} seeds · "
            f"entropy {entropy} · {prediction}"
        )
        oracle(f"[PATTERN] Loaded {pat_id}: {msg}")
        return True, msg

    # ── Unload (all at once — called by JSONManager for bulk clear) ───
    def unload(self, log, oracle) -> Tuple[bool, str]:
        n = len(self._patterns)
        self._patterns.clear()
        self._pat_path.clear()
        return True, f"Removed {n} pattern file(s)"

    # ── Unload one specific pattern (called by JSONManager per file) ──
    def unload_one(
        self, pat_id: str, log, oracle
    ) -> Tuple[bool, str]:
        """Remove a single pattern by its id string."""
        if pat_id not in self._patterns:
            return False, f"Pattern '{pat_id}' not found in registry"
        name = self._patterns[pat_id].get("name", pat_id)
        del self._patterns[pat_id]
        self._pat_path.pop(pat_id, None)
        oracle(f"[PATTERN] Unloaded pattern '{name}'")
        return True, f"Removed pattern '{name}'"

    # ── Read access for other subsystems ─────────────────────────────
    def get_patterns(self) -> Dict[str, dict]:
        """Return a copy of all currently loaded patterns."""
        return dict(self._patterns)

    # ── Summary ───────────────────────────────────────────────────────
    def summary(self) -> str:
        if not self._patterns:
            return "—"
        names = ", ".join(
            d.get("name", pid) for pid, d in list(self._patterns.items())[:3]
        )
        suffix = f" … +{len(self._patterns)-3} more" if len(self._patterns) > 3 else ""
        return f"Patterns · {len(self._patterns)} loaded · {names}{suffix}"


# ══════════════════════════════════════════════════════════════════════
# JSON Manager  —  the single public interface used by the GUI
# ══════════════════════════════════════════════════════════════════════

class JSONManager:
    """
    Unified JSON file registry for the ECU Simulator.

    Usage (in ECU_GUI.__init__)
    ───────────────────────────
        self.json_mgr = JSONManager(self.log_uds, self.log_oracle)
        self.json_mgr.register_handler(VulnerabilityHandler(ecu.cfg, rebuild_engine))
        self.json_mgr.register_handler(PatternHandler())

    Then wire the two GUI buttons:
        Load JSON   → self.json_mgr.load_file(path)
        Unload JSON → self.json_mgr.unload_file(path)
    """

    def __init__(
        self,
        log:    Callable[[str], None],
        oracle: Callable[[str], None],
    ):
        self._log    = log
        self._oracle = oracle

        # Ordered list of handlers attempted during auto-detection.
        # More-specific handlers should be registered before more-general ones.
        self._handlers: List[JSONHandler] = []

        # Registry: absolute_path → record dict
        # record = {path, basename, type_id, handler, data, display_name}
        self._loaded: Dict[str, dict] = {}

    # ── Handler registration ──────────────────────────────────────────

    def register_handler(self, handler: JSONHandler) -> None:
        """
        Register a JSON type handler.

        Handlers are tried in the order they are registered; the first
        whose can_handle() returns True wins.  Register more-specific
        handlers before catch-all ones.
        """
        self._handlers.append(handler)

    # ── Core operations ───────────────────────────────────────────────

    def load_file(self, path: str) -> Tuple[bool, str]:
        """
        Validate, auto-detect, and load a JSON file.

        Returns (success: bool, user-facing message: str).

        Steps
        ─────
        1. Duplicate check — same path already loaded?
        2. File existence check.
        3. JSON parse + schema validation (root must be an object).
        4. Auto-detection — iterate handlers, pick the first match.
        5. Delegate to handler.load().
        6. Store record in registry on success.
        """
        basename = os.path.basename(path)
        abs_path = os.path.abspath(path)

        # ── 1. Duplicate guard ────────────────────────────────────────
        if abs_path in self._loaded:
            return False, f"'{basename}' is already loaded"

        # ── 2. Existence ──────────────────────────────────────────────
        if not os.path.isfile(abs_path):
            return False, f"File not found: {path}"

        # ── 3. Parse & validate ───────────────────────────────────────
        try:
            with open(abs_path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except json.JSONDecodeError as exc:
            return False, f"Malformed JSON in '{basename}': {exc}"
        except OSError as exc:
            return False, f"Cannot read '{basename}': {exc}"

        if not isinstance(data, dict):
            return (
                False,
                f"Unsupported JSON structure in '{basename}' "
                f"(root must be an object, got {type(data).__name__})",
            )

        # ── 4. AUTO-DETECTION ─────────────────────────────────────────
        # Iterate handlers in registration order; first match wins.
        handler = self._auto_detect(data)
        if handler is None:
            keys_preview = ", ".join(list(data.keys())[:6])
            return (
                False,
                f"Unrecognised JSON structure in '{basename}'. "
                f"Top-level keys: [{keys_preview}]",
            )

        # ── 5. Delegate load ─────────────────────────────────────────
        ok, msg = handler.load(data, abs_path, self._log, self._oracle)
        if not ok:
            return False, msg

        # ── 6. Register ──────────────────────────────────────────────
        self._loaded[abs_path] = {
            "path":         abs_path,
            "basename":     basename,
            "type_id":      handler.TYPE_ID,
            "handler":      handler,
            "data":         data,
            # data.get("id") gives a human-readable label where available
            "display_name": (
                data.get("id")
                or data.get("ecu_profile")
                or os.path.splitext(basename)[0]
            ),
        }

        self._log(f"[JSON] ✔ Loaded [{handler.TYPE_ID}] '{basename}'")
        return True, msg

    def unload_file(self, path: str) -> Tuple[bool, str]:
        """
        Unload one loaded file and clear its associated simulator state.

        Returns (success: bool, user-facing message: str).
        """
        abs_path = os.path.abspath(path)
        if abs_path not in self._loaded:
            return False, f"'{os.path.basename(path)}' is not in the loaded registry"

        record   = self._loaded[abs_path]
        handler  = record["handler"]
        basename = record["basename"]

        # PatternHandler keeps multiple patterns; unload just this one.
        if isinstance(handler, PatternHandler):
            pat_id   = record["data"].get("id", "")
            ok, msg  = handler.unload_one(pat_id, self._log, self._oracle)
        else:
            ok, msg  = handler.unload(self._log, self._oracle)

        if ok:
            del self._loaded[abs_path]
            self._log(f"[JSON] ✖ Unloaded '{basename}'")

        return ok, msg

    # ── Query helpers used by the GUI ─────────────────────────────────

    def get_loaded_records(self) -> List[dict]:
        """Return a list of all loaded-file records (copies)."""
        return list(self._loaded.values())

    def is_loaded(self, path: str) -> bool:
        return os.path.abspath(path) in self._loaded

    def count(self) -> int:
        return len(self._loaded)

    # ── Internal ─────────────────────────────────────────────────────

    def _auto_detect(self, data: dict) -> Optional[JSONHandler]:
        """
        Iterate handlers in registration order; return the first that
        can_handle() the given data dict.  Returns None if no match.
        """
        for handler in self._handlers:
            try:
                if handler.can_handle(data):
                    return handler
            except Exception:
                # A broken handler must never block other handlers.
                continue
        return None
