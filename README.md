# JOCKY

### Digital Forensics & Incident Response Framework

**JOCKY** is a modular, desktop-based **Digital Forensics and Incident Response (DFIR) framework** designed for structured endpoint investigation.

It provides a unified environment for **system evidence collection, process and network analysis, persistence analysis, file hashing, detection, evidence integrity verification, alert management, investigation automation, case management, audit logging, and forensic reporting.**

JOCKY combines a Python-based forensic backend with a **PySide6 desktop interface**, while preserving the original command-line workflow.

---

## Key Capabilities

### 🔍 Endpoint Evidence Collection

JOCKY can collect multiple categories of endpoint artifacts:

* System information
* Local users
* Running processes
* Active network connections
* Persistence mechanisms
* File metadata
* SHA-256 file hashes

Collected artifacts are stored as structured JSON evidence.

---

### ⚙️ Process Forensics

JOCKY uses **psutil** to inspect running processes.

For each process, the framework can collect:

* Process ID
* Process name
* Executable path
* Username
* CPU utilization
* Memory utilization
* Memory usage in MB

The collected process data can then be analyzed by the detection engine.

---

### 🌐 Network Forensics

The network collector uses `psutil` to inspect active Internet connections.

JOCKY records:

* Connection family
* Connection type
* Connection status
* Process ID
* Local IP and port
* Remote IP and port

The detection layer can identify configured suspicious network patterns, including established connections using uncommon remote ports.

---

### 🔐 Persistence Analysis

JOCKY analyzes common persistence mechanisms across operating systems.

#### Windows

It checks:

* Registry `Run`
* Registry `RunOnce`
* Startup folder

#### Linux

It checks:

* Cron locations
* Systemd services
* User autostart entries

This allows investigators to identify applications configured for automatic execution.

---

### 📁 File Forensics

The file collector recursively examines a selected directory.

For collected files, JOCKY records metadata such as:

* File path
* File name
* Extension
* File size
* Creation time
* Modification time
* Access time

A **SHA-256 cryptographic hash** is calculated for every collected file.

This provides a reproducible cryptographic fingerprint for the collected file content.

---

## 🧠 Detection Engine

JOCKY includes a configurable, read-only defensive detection engine.

Current detection logic includes:

### Suspicious Process Names

The framework can identify configured suspicious tools/process names through the existing process detection module.

### Writable Execution Paths

Processes executing from potentially user-writable locations can generate findings.

Examples include paths associated with:

* Temporary directories
* Downloads
* `/tmp`
* `/dev/shm`
* User cache/configuration locations

### Uncommon Remote Ports

Established connections to global remote IP addresses using ports outside the configured common-port set can generate a finding.

### Writable Persistence Paths

Persistence entries pointing to potentially user-writable locations can generate higher-severity findings.

---

## 🚨 Alert System

Detection results are converted into structured alerts.

Each alert contains information such as:

* Alert ID
* Host
* Detection rule
* Severity
* Target
* Reason
* Timestamp
* Investigation status

Alert statuses can be managed through the GUI, allowing findings to move through an investigation workflow.

---

## 📊 Risk Scoring

JOCKY provides a simple risk-prioritization mechanism based on generated findings.

Severity levels contribute different weights:

| Severity | Points |
| -------- | -----: |
| Critical |     40 |
| High     |     25 |
| Medium   |     10 |
| Low      |      3 |

The total score is capped at **100** and mapped to a risk level.

The risk score is intended to help investigators prioritize findings; it is not itself proof of compromise.

---

# 🔏 Evidence Integrity

Evidence integrity is one of the core components of JOCKY.

Evidence artifacts are registered in an **SQLite database** with:

* Evidence ID
* Evidence type
* File path
* SHA-256 hash
* Collection timestamp

During verification, JOCKY calculates the current hash again and compares it with the stored hash.

Evidence can be reported as:

* **OK** — current hash matches
* **MODIFIED** — hash changed
* **MISSING** — evidence file is unavailable
* **SUPERSEDED** — an older evidence record was replaced by a newer collection

This provides an integrity and history mechanism around collected forensic artifacts.

---

# 🗄️ Evidence Database

JOCKY uses **SQLite** for evidence and investigation storage.

The database contains the original evidence records and additional application-level tables for:

* Alerts
* Cases
* Audit events

The evidence files themselves are maintained separately under the `evidence/` directory.

This separates the collected artifacts from the application workflow data.

---

# 🖥️ Desktop GUI

The desktop interface is built using **PySide6**.

The GUI acts as a frontend over the existing JOCKY backend and CLI functions rather than duplicating forensic logic.

The application provides dedicated interfaces for:

* Dashboard
* System information
* Processes
* Network
* Persistence
* Files
* Evidence
* Alerts
* Cases
* Reports
* Audit Logs
* JOCKY IDE

The dashboard provides a consolidated view of:

* Process count
* Network connections
* Persistence entries
* Hashed files
* Open alerts
* Risk level
* CPU usage
* Memory usage
* Top memory-consuming processes
* Recent alerts

---

# 🧩 JOCKY Scripting Language

One of the distinctive components of the project is the **JOCKY scripting system**.

Investigators can define repeatable forensic workflows using `.jky` scripts.

For example:

```text
scan system
scan processes
scan network
scan files "scripts"
scan persistence
report
```

The scripting pipeline is:

```text
JOCKY Script
     ↓
Parser
     ↓
AST
     ↓
IR Compiler
     ↓
JOCKY IR
     ↓
IR Executor
     ↓
Forensic Actions
```

This allows investigation workflows to be represented as programmable instructions instead of requiring every operation to be manually executed from the GUI.

---

# ⚙️ AST and Intermediate Representation

The JOCKY compiler contains separate components for:

* Grammar definition
* Parsing
* AST construction
* AST representation
* IR compilation
* IR instructions
* IR program representation
* Execution

This creates a clear separation between:

**What the investigator writes → how it is represented → how it is executed.**

It also makes the scripting system easier to extend with additional forensic operations.

---

# 📋 Case Management

JOCKY provides a case-management layer for organizing investigations.

A case can contain:

* Case ID
* Title
* Severity
* Status
* Investigator
* Creation timestamp
* Associated report

This allows alerts and forensic findings to be moved into a structured investigation context.

---

# 📝 Forensic Reporting

JOCKY can generate a forensic report from the collected evidence and investigation findings.

Reports are stored under the `reports/` directory.

The generated report can also be associated with a case.

JOCKY calculates a **SHA-256 hash for the generated report**, providing an integrity reference for the final investigation artifact.

---

# 📜 Audit Logging

The application maintains an audit trail for important investigation activities.

Examples include:

* Command execution
* Failed command execution
* Evidence verification
* Alert status changes
* Case creation
* Report generation

This provides traceability of actions performed during an investigation.

---

# 🏗️ Architecture

At a high level, JOCKY follows this architecture:

```text
                    ┌─────────────────────┐
                    │    PySide6 GUI      │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │     JOCKY Core       │
                    │      GUI Facade      │
                    └──────────┬──────────┘
                               │
              ┌────────────────┼────────────────┐
              ▼                ▼                ▼
       ┌─────────────┐  ┌─────────────┐  ┌─────────────┐
       │  Evidence   │  │  Detection  │  │   Cases &   │
       │  Collectors │  │   Engine    │  │   Alerts    │
       └──────┬──────┘  └─────────────┘  └─────────────┘
              │
              ▼
       ┌─────────────────┐
       │ JSON Evidence   │
       │ + SHA-256 Hash  │
       └────────┬────────┘
                │
                ▼
       ┌─────────────────┐
       │ SQLite Evidence │
       │    Database     │
       └────────┬────────┘
                │
                ▼
       ┌─────────────────┐
       │ Investigation   │
       │   & Reporting   │
       └─────────────────┘
```

The scripting path operates separately alongside the forensic backend:

```text
.jky Script
    ↓
Parser
    ↓
AST
    ↓
IR Compiler
    ↓
IR Instructions
    ↓
Executor
    ↓
Evidence / Investigation
```

---

# 📂 Project Structure

```text
JOCKY/
│
├── main.py
├── requirements.txt
├── pyproject.toml
├── run.bat
│
├── gui/
│   ├── main_window.py
│   ├── pages.py
│   └── common.py
│
├── jocky/
│   ├── core.py
│   ├── store.py
│   │
│   ├── cli/
│   │   └── main.py
│   │
│   ├── evidence/
│   │   ├── collector.py
│   │   ├── database.py
│   │   ├── hash_utils.py
│   │   ├── process_collector.py
│   │   ├── network_collector.py
│   │   ├── persistence_collector.py
│   │   ├── file_collector.py
│   │   └── user_collector.py
│   │
│   ├── detection/
│   │   ├── rules.py
│   │   └── process_detector.py
│   │
│   ├── compiler/
│   │   ├── grammar.lark
│   │   ├── parser.py
│   │   ├── ast.py
│   │   ├── ast_builder.py
│   │   └── ir_compiler.py
│   │
│   ├── ir/
│   │   ├── instructions.py
│   │   └── program.py
│   │
│   ├── engine/
│   │   └── executor.py
│   │
│   └── report/
│       └── generator.py
│
├── scripts/
│   ├── basic.jky
│   ├── quick_scan.jky
│   ├── files_scan.jky
│   ├── persistence_check.jky
│   └── full_scan.py
│
├── evidence/
│   ├── system_info.json
│   ├── processes.json
│   ├── network_connections.json
│   ├── persistence.json
│   ├── file_hashes.json
│   ├── findings.json
│   └── jocky.db
│
└── reports/
    └── forensic_report.txt
```

---

# 🛠️ Technology Stack

| Technology       | Purpose                                 |
| ---------------- | --------------------------------------- |
| **Python 3.12+** | Core implementation                     |
| **PySide6**      | Desktop GUI                             |
| **psutil**       | Process and network information         |
| **Typer**        | CLI interface                           |
| **Lark**         | JOCKY language parsing                  |
| **SQLite**       | Evidence, alert, case and audit storage |
| **SHA-256**      | Evidence and report integrity           |
| **Rich**         | CLI output formatting                   |
| **Pytest**       | Testing                                 |

---

# 🚀 Installation

### Requirements

* Python **3.12+**
* Windows or Linux
* Administrator/root privileges may be required for complete process and network visibility.

### Setup

```bash
git clone <your-repository-url>
cd JOCKY

python -m venv .venv
```

### Windows

```bash
.venv\Scripts\activate
pip install -r requirements.txt
python main.py
```

### Linux

```bash
source .venv/bin/activate
pip install -r requirements.txt
python main.py
```

---

# 💻 CLI Usage

JOCKY can also be used directly from the command line.

Examples:

```bash
jocky system-info
jocky processes
jocky network
jocky persistence
jocky files <directory>
jocky scan
jocky evidence
jocky report
jocky parse <script.jky>
jocky compile <script.jky>
jocky run <script.jky>
jocky investigate
```

The GUI and CLI share the same underlying forensic backend.

---

# 🔬 Example Investigation Workflow

A typical investigation can follow:

```text
1. Collect system information
2. Collect running processes
3. Collect network connections
4. Inspect persistence mechanisms
5. Hash relevant files
6. Run detection rules
7. Review generated alerts
8. Verify evidence integrity
9. Create an investigation case
10. Generate the forensic report
```

For repeatable investigations, the same workflow can be automated through a JOCKY script.

---

# 🔒 Security Design Principles

JOCKY is designed around several forensic principles:

* **Structured evidence collection**
* **Cryptographic evidence fingerprinting**
* **Read-only defensive detection**
* **Repeatable investigation workflows**
* **Evidence integrity verification**
* **Auditability**
* **Modular architecture**
* **Human-readable forensic reporting**

---

# ⚠️ Important Note

JOCKY is a **defensive forensic and investigation framework**.

Detection rules are configured indicators designed to help analysts identify activity requiring further investigation. A generated alert or risk score should not by itself be interpreted as definitive proof of malicious activity or system compromise.

For complete forensic acquisition or legally admissible investigations, additional specialized procedures and validated forensic tooling may be required.

---

# 🎯 Project Objective

The objective of JOCKY is to provide investigators with a unified and extensible platform for endpoint investigation.

Instead of switching between multiple utilities for collection, detection, hashing, investigation, and reporting, JOCKY provides these capabilities through one integrated framework.

The core investigation lifecycle is:

**Collect → Preserve → Detect → Investigate → Report**

---

## JOCKY

**Digital Forensics & Incident Response Framework**

> Collect reliable evidence.
> Analyze systematically.
> Preserve integrity.
> Investigate with confidence.
