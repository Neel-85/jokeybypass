# JOCKY Desktop (PySide6)

Your full JOCKY backend (`jocky/` package, `scripts/`, `evidence/`, `reports/`, CLI) + a single-window GUI.
The GUI calls the ORIGINAL CLI functions (jocky/cli/main.py) and shows their output in the Console dock,
so every backend command has a page/button. The `jocky` CLI still works as before.

## Run (Python 3.12+)
    python -m venv .venv
    .venv\Scripts\activate            (Linux: source .venv/bin/activate)
    pip install -r requirements.txt
    python main.py                    (or double-click run.bat)

Run the terminal as Administrator for full process/network visibility.

## Backend command -> GUI
| CLI                    | GUI                                            |
|------------------------|------------------------------------------------|
| system-info            | System page (+ local users via user_collector) |
| processes              | Processes page                                 |
| network                | Network page                                   |
| persistence            | Persistence page                               |
| files DIR              | Files page (directory picker)                  |
| scan / investigate     | top-bar buttons                                |
| report                 | Cases / Reports page                           |
| evidence               | Evidence page (+ SHA-256 integrity verify)     |
| parse / compile / run  | JOCKY IDE buttons                              |
| version / status / all | Console dock -> command dropdown               |

Extra (from the web prototype): Dashboard with live monitor (auto refresh), Alerts workflow, Cases, Audit Logs.

## Changes made to the original backend (minimal)
- `scan files "dir"` was in grammar.lark but not in AST/IR/executor -> added (ast.py, ast_builder.py, instructions.py, ir_compiler.py).
- executor.py now executes `scan persistence` and `scan files` (they compiled but failed at run time).
- grammar.lark: `# comments` allowed.
- New files only: jocky/core.py (GUI facade), jocky/store.py (alerts/cases/audit tables), jocky/detection/rules.py (extra rules;
  process_detector.py untouched), gui/, main.py, run.bat.

Evidence integrity: each scan overwrites the evidence JSON, so older DB records show as SUPERSEDED; only the newest record per file is checked.
