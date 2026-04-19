# Password Strength Analyzer (Tkinter)

A Python desktop app that:

- Analyzes password strength with a 0–100 score (minimum length **16 characters**)
- Separates **Results** (facts from checks) from **Recommendations** (what to improve)
- Detects weak patterns (repeats, sequences, keyboard patterns, basic dictionary words)
- Checks against a common-password list (from a `.txt` file or optional SQLite index)
- Suggests stronger passwords (random generator, at least 16 characters)
- **Hashes** passwords with salted PBKDF2-SHA256 for safe storage
- **Encrypts** a copy with **AES-256-GCM** (using a user-provided master password) so entries can be **restored** from a local SQLite database

## Project structure

- `main.py`: entry point
- `password_analyzer/`: core modules (analysis, scoring, feedback, generator, GUI, crypto, storage)
- `data/common_passwords.txt`: common passwords list (editable)
- `data/password_hashes.sqlite`: local vault (created automatically)

## Requirements

- Python **3.10+** recommended (Python 3.8+ should work for most of the code)
- Install dependencies:

```bash
pip install -r requirements.txt
```

The only third-party package is **`cryptography`**, used for AES-GCM encryption of stored passwords.

## How to run (Windows / macOS / Linux)

1. Install Python from the official website: https://www.python.org/downloads/
2. Download/unzip this project folder.
3. Open a terminal in the project folder and install requirements (see above).
4. Run the app:

```bash
python main.py
```

If `python` doesn’t work, try `python3 main.py`.

## Troubleshooting: “No module named _tkinter”

This means your Python was installed **without Tkinter GUI support**.

- **Windows / macOS (python.org installer)**: reinstall Python and ensure “Tcl/Tk” is included.
- **Linux (Debian/Ubuntu)**:

```bash
sudo apt-get update
sudo apt-get install -y python3-tk
```

- **macOS (Homebrew Python)**:

```bash
brew install python-tk@3.14
/opt/homebrew/bin/python3 main.py
```

- **macOS (pyenv)**: rebuild Python with Tcl/Tk (see older README versions or Python docs).

### Cursor/VS Code note

The IDE may mark a Python interpreter as “Recommended” even if it lacks Tkinter. Select an interpreter that includes Tkinter.

## How the common-password check works

- The app loads a common-password list at startup and checks **exact matches**.
- For **small/medium lists**, it uses `data/common_passwords.txt`.
- For **very large lists (millions)**, use the optional SQLite index `data/common_passwords.sqlite` (recommended).

## Use SecLists for the common-password list (recommended)

```bash
python scripts/download_seclists_common_passwords.py
python main.py
```

## Password hashing & encrypted storage

- **PBKDF2-SHA256** (salted, 200k iterations): one-way hash for verification-style storage. Format:  
  `pbkdf2_sha256$<iterations>$<saltB64>$<hashB64>`
- **AES-256-GCM**: encrypts the password so it can be **restored** with the same **master password** used when saving.
- **Database**: `data/password_hashes.sqlite`

Older rows may contain only a hash (`hash-only` in the list); new saves store both hash and encrypted payload (`restorable`).

## Millions of common passwords (SQLite index)

```bash
python scripts/build_common_passwords_sqlite.py
python main.py
```

