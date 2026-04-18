---
name: Project toolchain — venv with uv
description: The project uses uv to manage a .venv at the thesis root; tests run via .venv/bin/python -m pytest tests/ -v
type: project
---

The venv is created with `uv venv .venv` and packages installed via `uv pip install`. Always use `.venv/bin/python` (or `.venv/bin/pytest`) to run code — do NOT use the system `python`.

**Why:** User rejected a plain `pip install` and asked for uv explicitly on 2026-04-15.
**How to apply:** Any time a new dependency needs installing, use `uv pip install <pkg>`. Reference the venv binary for running scripts/tests.
