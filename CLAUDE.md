# OmniMTK Forensic Suite - Global Directive

## 1. Project Identity & Architecture
- This is a Bare-Metal Digital Forensics & Hardware Exploitation tool.
- **ABSOLUTE RULE:** The project is a SINGLE-FILE MONOLITH (`omni_mtk_samsung.py`). NEVER split it into multiple modules (core/, gui/, cli/).
- **Execution:** It must run flawlessly in both PyQt6 GUI mode and Headless CLI mode (`--cli`).

## 2. Memory & I/O Resilience (Zero-Copy)
- **FORBIDDEN:** `read_bytes()`, `read()`, or loading entire files into RAM.
- **MANDATORY:** Always use `mmap.mmap(fd, _get_real_size(fd), access=mmap.ACCESS_READ)` for binary ingestion. 
- You MUST handle Block Devices (`/dev/sdb`, `\\.\PhysicalDrive0`) safely without `os.path.getsize()` crashing.

## 3. Forensic Determinism & OpSec
- **Immutable Blockchain Journal:** All forensic actions MUST be logged with a chained SHA-256 hash.
- **Zero Disk Trace:** NEVER write plaintext keys or payloads to disk automatically. Keep everything in RAM unless the user explicitly requests an export.
- **No Silent Failures:** NEVER use `except Exception: pass`. If something fails, fail loudly with a `sys.stderr` print or a GUI critical alert.

## 4. Testing & Verification
- You have terminal execution capabilities. Do NOT guess if your code works.
- After modifying the monolith, you MUST run `python -m py_compile omni_mtk_samsung.py` to check for syntax errors.
- You MUST run `python test_v11_sandbox.py` (or the latest test suite) and VERIFY that all tests pass before presenting the solution to the user.