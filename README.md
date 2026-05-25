# ECU Simulator with UDS & Vulnerability Injection

## Overview

ECU Simulator is a Python-based automotive Electronic Control Unit (ECU) simulation framework designed for testing, cybersecurity research, fuzzing validation, and UDS protocol experimentation.

The simulator supports:

- UDS (Unified Diagnostic Services)
- ISO-TP communication
- Virtual ECU behavior simulation
- Vulnerability injection engine
- JSON-based load pattern simulation
- Security testing and fuzzing support
- Logging and monitoring utilities

This project is useful for:

- Automotive cybersecurity research
- ECU fuzz testing
- UDS protocol validation
- Virtual ECU experimentation
- Diagnostic communication testing
- Academic and research projects

---

# Features

## UDS Protocol Support

Implemented UDS diagnostic services include:

- Diagnostic Session Control
- ECU Reset
- Read Data By Identifier
- Security Access
- Routine Control
- Tester Present

---

## Virtual ECU Simulation

The simulator provides:

- ECU memory emulation
- ECU state management
- Diagnostic response generation
- Request handling
- ISO-TP server communication

---

## Vulnerability Injection Engine

The project supports configurable ECU vulnerabilities using:

- `vulnerabilities.json`
- `vulnerability_engine.py`
- `vulnerability_config.py`

This enables:

- Security testing
- Penetration testing
- Fuzzing validation
- Attack simulation

---

## Pattern-Based Simulation

The `patterns/` directory contains multiple ECU traffic and behavior simulation patterns such as:

- Static seed generation
- Linear counters
- XOR masked counters
- Timestamp patterns
- Weak PRNG simulation
- Alternating patterns

These patterns help in:

- Fuzzing
- Replay testing
- Protocol analysis
- Security validation

---

# Project Structure

```text
ECU_SIMULATOR/
│
├── main.py
├── gui.py
├── virtual_ecu.py
├── uds_core.py
├── uds_helpers.py
├── uds_constants.py
├── ecu_memory.py
├── ecu_state.py
├── isotp_server.py
├── json_manager.py
├── logger.py
├── vulnerabilities.json
├── vulnerability_engine.py
├── vulnerability_config.py
├── config.py
│
├── patterns/
│   ├── PAT-001_static_seed.json
│   ├── PAT-002_repeating_loop_period4.json
│   ├── PAT-003_linear_counter_plus1.json
│   ├── PAT-004_linear_counter_plus256.json
│   ├── PAT-005_timestamp_step50.json
│   ├── PAT-006_weak_lfsr_period8.json
│   ├── PAT-007_pingpong_alternating.json
│   ├── PAT-008_xor_masked_counter.json
│   └── PAT-009_secure_prng_baseline.json
```

---

# Requirements

Install Python dependencies:

```bash
pip install -r requirements.txt
```

If requirements file is unavailable, install manually:

```bash
pip install python-can isotp tkinter
```

---

# Running the Simulator

Run the application:

```bash
python main.py
```

---

# Use Cases

- Automotive ECU testing
- UDS protocol learning
- Cybersecurity experimentation
- ECU fuzzing validation
- Diagnostic simulation
- Virtual ECU development

---

# Future Improvements

- CAN FD support
- DoIP integration
- Real hardware ECU communication
- Advanced fuzzing automation
- OTA testing support
- Secure boot simulation

---

# Author

Vinayak Ganjihal

---

# Disclaimer

This project is intended only for:

- Educational purposes
- Research
- Authorized cybersecurity testing

Do not use this project for unauthorized activities.
