# ECU Simulator with UDS & Vulnerability Injection

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10%2B-blue?style=for-the-badge&logo=python"/>
  <img src="https://img.shields.io/badge/Protocol-UDS%20%7C%20ISO--TP-green?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/Domain-Automotive%20Cybersecurity-red?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/GUI-Tkinter-orange?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/License-Research%20%26%20Education-lightgrey?style=for-the-badge"/>
</p>

---

## Overview

**ECU Simulator** is a Python-based automotive Electronic Control Unit (ECU) simulation framework designed for cybersecurity research, UDS protocol experimentation, fuzzing validation, and diagnostic communication testing.

The simulator provides a realistic virtual ECU environment with a live phosphor-terminal GUI, full UDS service handling, ISO-TP transport, a configurable vulnerability injection engine, and a **unified JSON management system** that automatically identifies and applies any JSON configuration file — no manual type selection required.

---

## What's New — Unified JSON Manager

> Replaces all type-specific JSON buttons with a single, generic **Load JSON / Unload JSON** interface.

Previously the GUI exposed separate controls for vulnerability files and pattern files. The refactored system introduces `json_manager.py`, which handles every JSON type through one common pipeline:

```
User clicks "Load JSON"
        │
        ▼
   File Dialog (any .json)
        │
        ▼
   JSONManager.load_file()
    ├─ Validate (malformed JSON rejected with clear error)
    ├─ Duplicate check (same file cannot be loaded twice)
    ├─ AUTO-DETECT → can_handle() tried on each registered handler
    │       ├─ VulnerabilityHandler  (ecu_profile + vulnerabilities[])
    │       ├─ PatternHandler        (seeds / seeds_hex + PAT- id)
    │       └─ [future handlers added here — zero GUI changes needed]
    └─ Handler.load() → applies config to simulator subsystem
        │
        ▼
   Status bar updated  ·  File listed in Unload dialog
```

### Key behaviours

| Behaviour | Detail |
|-----------|--------|
| Single button for all JSON types | `LOAD JSON` opens a plain file dialog — no type label shown |
| Auto-detection | Structure-based; handlers are tried in registration order |
| Multi-file registry | Multiple JSON files can be loaded simultaneously |
| Selective unload | `UNLOAD JSON` opens a listbox — pick one or many files to remove |
| Status area | Every load/unload result (file name, type, rule count) is shown inline |
| Duplicate prevention | Loading the same path twice is blocked with a clear message |
| Malformed JSON | Caught before any handler is called; error shown, no state changed |
| Unknown structure | Rejected gracefully; top-level keys shown to aid diagnosis |
| Extensible | New JSON types: subclass `JSONHandler`, register — no GUI change |

---

## Features

### UDS Protocol Support

Full implementation of the most common UDS diagnostic services:

| Service ID | Service Name |
|---|---|
| `0x10` | Diagnostic Session Control |
| `0x11` | ECU Reset |
| `0x22` | Read Data By Identifier |
| `0x27` | Security Access |
| `0x2E` | Write Data By Identifier |
| `0x31` | Routine Control |
| `0x3E` | Tester Present |

---

### Virtual ECU Simulation

The simulator provides a fully software-defined ECU environment:

- **ECU Memory Emulation** — 4 KB addressable virtual memory with reset support
- **ECU State Management** — session tracking, security levels, fault/hang states, boot counter
- **ISO-TP Server** — full segmentation and reassembly over virtual CAN (`vcan0`)
- **CAN Bus Sniffer** — parallel raw-frame monitoring feeding the vulnerability engine
- **Diagnostic Response Generation** — positive responses, NRC handling, P2/P2* timing

---

### Vulnerability Injection Engine

Configurable ECU vulnerabilities are declared in `vulnerabilities.json` and executed by `vulnerability_engine.py` at runtime. Supported vulnerability classes:

| ID | Name | Effect |
|---|---|---|
| VULN-001 | VIN Write Overflow | CRASH — stops responding |
| VULN-002 | Security Bypass Magic Byte | Bypasses authentication |
| VULN-003 | Resource Exhaustion DoS | 5-second hang |
| VULN-004 | ISO-TP Segment Overlap | Silent reassembly crash |
| VULN-005 | Diagnostic Session Leaking | Illegal session transition accepted |
| VULN-006 | Weak Seed Entropy | Constant seed `0xDEADBEEF` returned |

Each vulnerability can be individually `enabled` or `disabled` without changing code.

---

### Pattern-Based Simulation

The `patterns/` directory contains seed-pattern JSON files used for entropy analysis, fuzzing, and replay testing:

| Pattern | Description | Entropy |
|---|---|---|
| PAT-001 | Static Seed | 0.0 bits — CRITICAL |
| PAT-002 | Repeating Loop (period 4) | Very low |
| PAT-003 | Linear Counter +1 | Low |
| PAT-004 | Linear Counter +256 | Low |
| PAT-005 | Timestamp Step 50 | Medium |
| PAT-006 | Weak LFSR (period 8) | Low |
| PAT-007 | Ping-Pong Alternating | Very low |
| PAT-008 | XOR Masked Counter | Medium |
| PAT-009 | Secure PRNG Baseline | High — reference |

---

### GUI — Phosphor Terminal Console

The GUI is built entirely in Tkinter with a phosphor-terminal aesthetic. Key panels:

- **UDS Diagnostic Log** — every request and response with timestamps
- **CAN Frame Log** — raw ISO-TP frames, IDs, DLC, data bytes
- **Oracle / Vuln Log** — vulnerability trigger events with payload context
- **JSON Status Bar** — lists all loaded files; shows load/unload feedback
- **ECU State Row** — session badge, security lock indicator, boot counter, P2 timeout
- **MSG FLOW** — animated packet-flow diagram with direction and colour coding
- **CAN Density Graph** — live bar chart of frame rate

---

## Project Structure

```text
ECU_SIMULATOR/
│
├── main.py                          # Entry point — launches the Tkinter GUI
├── gui.py                           # GUI: phosphor console, unified JSON controls
├── json_manager.py                  # ★ NEW — unified JSON registry & auto-detection
│
├── virtual_ecu.py                   # VirtualECU: main loop, request dispatch
├── uds_core.py                      # UDS service handlers
├── uds_helpers.py                   # Formatting utilities (hex, NRC names)
├── uds_constants.py                 # SID / NRC constant definitions
│
├── ecu_memory.py                    # Virtual RAM + NVM emulation
├── ecu_state.py                     # Session, security, fault, timing state
├── isotp_server.py                  # ISO-TP segmentation / reassembly over CAN
│
├── vulnerability_config.py          # Parses vulnerabilities.json into config object
├── vulnerability_engine.py          # Evaluates requests against active rules
├── vulnerabilities.json             # Default vulnerability profile (Gateway_ECU_Sim)
│
├── logger.py                        # Structured file + console logging
├── config.py                        # Interface, CAN IDs, default paths
│
└── patterns/
    ├── PAT-001_static_seed.json
    ├── PAT-002_repeating_loop_period4.json
    ├── PAT-003_linear_counter_plus1.json
    ├── PAT-004_linear_counter_plus256.json
    ├── PAT-005_timestamp_step50.json
    ├── PAT-006_weak_lfsr_period8.json
    ├── PAT-007_pingpong_alternating.json
    ├── PAT-008_xor_masked_counter.json
    └── PAT-009_secure_prng_baseline.json
```

---

## Requirements

### System prerequisites

```bash
# Linux — set up virtual CAN interface
sudo modprobe vcan
sudo ip link add dev vcan0 type vcan
sudo ip link set up vcan0
```

### Python dependencies

```bash
pip install python-can
```

> `tkinter` ships with the standard Python distribution. If missing on your system:
> ```bash
> sudo apt install python3-tk   # Debian / Ubuntu
> ```

---

## Running the Simulator

```bash
python main.py
```

The GUI window opens. The default `vulnerabilities.json` is loaded automatically on startup and appears in the JSON status bar. From there:

- Click **LOAD JSON** to load any additional `.json` file (vulnerability profiles, seed patterns, future types).
- Click **UNLOAD JSON** to open the file list and remove one or more loaded files.
- Click **EXPORT LOG** to save the full session log.

---


## Use Cases

- Automotive ECU security research and penetration testing
- UDS protocol learning and validation
- ECU fuzzing harness development
- Diagnostic communication simulation
- Vulnerability pattern replay and analysis
- Academic study of ISO 14229 / ISO 15765

---

