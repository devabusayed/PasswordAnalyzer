def main() -> None:
    try:
        from password_analyzer.gui import run_app
    except ModuleNotFoundError as e:
        missing = getattr(e, "name", "") or ""
        if missing in {"_tkinter", "tkinter"}:
            print(
                "Tkinter is not available in this Python installation.\n"
                "Fix:\n"
                "- Windows/macOS (python.org): reinstall Python and make sure Tcl/Tk is included\n"
                "- Linux (Debian/Ubuntu): sudo apt-get install python3-tk\n"
                "- macOS (Homebrew Python): brew install python-tk@3.14  (then run /opt/homebrew/bin/python3)\n"
                "- pyenv: your pyenv Python must be rebuilt with Tcl/Tk support (brew install tcl-tk, then reinstall Python via pyenv)\n"
                "\n"
                "Note: If `which python3` shows a pyenv shim, Homebrew installs won't affect it.\n"
            )
            raise SystemExit(2) from e
        raise

    run_app()


if __name__ == "__main__":
    main()
