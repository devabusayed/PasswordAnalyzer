# Password Strength Analyzer (Tkinter)

A Python desktop app that:

- Analyzes password strength
- Calculates a strength score (0–100)
- Detects weak patterns (repeats, sequences, keyboard patterns, basic dictionary words)
- Checks against a common-password list (from a `.txt` file)
- Provides feedback and improvement tips
- Suggests stronger passwords (random generator + passphrase generator)

## Project structure

- `main.py`: entry point
- `password_analyzer/`: core modules (analysis, scoring, feedback, generator, GUI)
- `data/common_passwords.txt`: common passwords list (editable)

## Requirements

- Python **3.10+** recommended (Python 3.8+ should work)
- No external packages required (uses Python standard library only)

## How to run (Windows / macOS / Linux)

1. Install Python from the official website: https://www.python.org/downloads/
2. Download/unzip this project folder.
3. Open a terminal in the project folder:
   - **Windows**: Shift + right-click inside the folder → “Open PowerShell window here”
   - **macOS**: open Terminal, then `cd` into the folder
   - **Linux**: open Terminal, then `cd` into the folder
4. Run the app:

```bash
python main.py
```

If `python` doesn’t work, try:

```bash
python3 main.py
```

## Troubleshooting: “No module named _tkinter”

This means your Python was installed **without Tkinter GUI support**.

- **Windows / macOS (python.org installer)**: reinstall Python and ensure “Tcl/Tk” is included.
- **Linux (Debian/Ubuntu)**:

```bash
sudo apt-get update
sudo apt-get install -y python3-tk
```

- **macOS (Homebrew Python)**:
  - Install Tk for the same Homebrew Python:

```bash
brew install python-tk@3.14
```

  - Then run the app explicitly with Homebrew Python:

```bash
/opt/homebrew/bin/python3 -c "import tkinter; print('Tk OK', tkinter.TkVersion)"
/opt/homebrew/bin/python3 main.py
```

- **macOS (pyenv)**:
  - `brew install python-tk@...` **does not fix** a pyenv Python (pyenv builds its own Python).
  - You must rebuild the pyenv Python *after* installing Tcl/Tk:

```bash
brew install tcl-tk

# (Optional) update pyenv so newer Python versions are available
cd "$(pyenv root)" && git pull
cd "$(pyenv root)"/plugins/python-build && git pull

export CPPFLAGS="-I$(brew --prefix tcl-tk)/include"
export LDFLAGS="-L$(brew --prefix tcl-tk)/lib"
export PKG_CONFIG_PATH="$(brew --prefix tcl-tk)/lib/pkgconfig"

pyenv install 3.11.8
pyenv local 3.11.8

python -c "import tkinter; print('Tk OK', tkinter.TkVersion)"
python main.py
```

### Cursor/VS Code note

The IDE may mark a Python interpreter as “Recommended” even if it lacks Tkinter. If Tkinter is missing, select an interpreter that has it (e.g. `/opt/homebrew/bin/python3`) or rebuild your pyenv Python with Tcl/Tk as shown above.

## How the common-password check works

- The app loads a common-password list at startup and checks **exact matches**.
- For **small/medium lists**, it uses `data/common_passwords.txt`.
- For **very large lists (millions)**, use the optional SQLite index `data/common_passwords.sqlite` (recommended).

## Use SecLists for the common-password list (recommended)

This project supports the **SecLists** dataset ([GitHub - danielmiessler/SecLists](https://github.com/danielmiessler/SecLists)).

To download a standard list (10k most common) into `data/common_passwords.txt`, run:

```bash
python scripts/download_seclists_common_passwords.py
```

Then start the app:

```bash
python main.py
```

### Use a different SecLists password file

The downloader accepts a `--url` argument pointing to a **raw GitHub** file URL.

Example:

```bash
python scripts/download_seclists_common_passwords.py --url "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10k-most-common.txt"
```

## Notes

- Keep the format as: **one password per line**.
- Very large lists can use a lot of RAM if kept as `.txt`. For millions of passwords, build the SQLite index below.

## Millions of common passwords (recommended: SQLite index)

1. Download a large list into `data/common_passwords.txt` (you can point the downloader to a bigger SecLists file URL).
2. Build the SQLite DB (one-time):

```bash
python scripts/build_common_passwords_sqlite.py
```

3. Run the app:

```bash
python main.py
```

When `data/common_passwords.sqlite` exists, the app will **automatically prefer it** (fast lookup, low RAM).

## Passphrase wordlist (download from internet)

By default, the app includes a small built-in list. For better passphrases, download a large wordlist (saved to `data/wordlist.txt`), then the app will use it automatically.

Download the default large list (EFF wordlist):

```bash
python scripts/download_passphrase_wordlist.py
```

Then run the app:

```bash
python main.py
```

