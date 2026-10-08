# Project Setup

## Prerequisites

- Python 3.10+
- Windows 10/11 (PowerShell 5.1+ or pwsh)

## One-Command Setup (Windows)

**Option A — PowerShell (recommended):**
```powershell
.\setup.ps1
```

**Option B — Double-click:**
Just double-click `setup.bat` in the project folder.

**Option C — Quick setup (skip heavy deps):**
```powershell
.\setup.ps1 quick
```

This will:
- Create a virtual environment at `.venv`
- Install pifw in editable mode with all extras
- Install extractor dependencies (PyMuPDF, python-docx, Pillow, etc.)
- Copy `.env.sample` to `.env`
- Run a smoke test to confirm everything works
- Run the full test suite

## All Commands

| Command | Description |
|---|---|
| `.\setup.ps1` | Full setup (venv + all deps + tests) |
| `.\setup.ps1 quick` | Quick setup (core + dev only) |
| `.\setup.ps1 test` | Run pytest test suite |
| `.\setup.ps1 lint` | Run ruff linter with auto-fix |
| `.\setup.ps1 demo` | Launch Streamlit demo app |
| `.\setup.ps1 proxy` | Start OpenAI-compatible proxy on port 8080 |
| `.\setup.ps1 eval` | Run evaluation harness and generate report |
| `.\setup.ps1 status` | Check what's installed and working |
| `.\setup.ps1 clean` | Remove venv, caches, and generated files |
| `.\setup.ps1 help` | Show help |

## Linux / macOS (Makefile)

```bash
cp .env.sample .env
make setup
make test
make demo
```

## Environment Variables

The project reads configuration from `.env` and environment variables prefixed with `PIFW_`.
See `.env.sample` for all available options.

## Optional: Tesseract OCR

For image-based attack detection (OCR extractor), install Tesseract:
- **Windows:** Download from [UB Mannheim](https://github.com/UB-Mannheim/tesseract/wiki)
- **Linux:** `sudo apt install tesseract-ocr`
- **macOS:** `brew install tesseract`

If not installed, the image extractor degrades gracefully.

## Optional: ML Classifier

The L2 ML classifier requires PyTorch + Transformers (~2GB download):
```powershell
.\.venv\Scripts\pip install pifw[ml]
```
If not installed, the classifier falls back to a lightweight heuristic scorer.
