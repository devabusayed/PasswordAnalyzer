from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from tkinter import messagebox

from .analysis import compute_penalty_points, detect_patterns
from .common_passwords import is_common_password, load_common_passwords_checker
from .crypto import hash_password_pbkdf2
from .feedback import generate_feedback
from .generator import generate_passphrase, generate_random_password
from .policy import MIN_PASSWORD_LENGTH
from .scoring import ScoreBreakdown, score_password
from .storage import list_password_hashes, save_password_hash


class PasswordStrengthApp(ttk.Frame):
    def __init__(self, master: tk.Tk) -> None:
        super().__init__(master, padding=16)
        self.master = master

        self._common_checker, common_meta = load_common_passwords_checker()
        self._common_loaded_count = common_meta.loaded_count

        self._password_var = tk.StringVar()
        self._show_var = tk.BooleanVar(value=False)
        self._strength_var = tk.StringVar(value="Strength: —")
        self._score_var = tk.StringVar(value="Score: —")
        self._hash_label_var = tk.StringVar(value="password")
        self._hash_output_var = tk.StringVar(value="Hash: —")
        self._hash_history_var = tk.StringVar(value="")

        self._progress_var = tk.IntVar(value=0)

        self._build_styles()
        self._build_ui()

    def _build_styles(self) -> None:
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass

        style.configure("Title.TLabel", font=("TkDefaultFont", 16, "bold"))
        style.configure("Subtle.TLabel", foreground="#5b616a")

        # Progressbar color styles.
        style.configure("Weak.Horizontal.TProgressbar", troughcolor="#e9ecef", background="#dc3545")
        style.configure("Moderate.Horizontal.TProgressbar", troughcolor="#e9ecef", background="#fd7e14")
        style.configure("Strong.Horizontal.TProgressbar", troughcolor="#e9ecef", background="#198754")

    def _build_ui(self) -> None:
        self.master.title("Password Strength Analyzer")
        self.master.minsize(720, 520)

        self.grid(row=0, column=0, sticky="nsew")
        self.master.rowconfigure(0, weight=1)
        self.master.columnconfigure(0, weight=1)
        self.columnconfigure(0, weight=1)
        self.rowconfigure(2, weight=1)

        header = ttk.Frame(self)
        header.grid(row=0, column=0, sticky="ew")
        header.columnconfigure(0, weight=1)

        ttk.Label(header, text="Password Strength Analyzer", style="Title.TLabel").grid(
            row=0, column=0, sticky="w"
        )
        ttk.Label(
            header,
            text="Checks strength, patterns, common-password list, and suggests stronger options.",
            style="Subtle.TLabel",
        ).grid(row=1, column=0, sticky="w", pady=(6, 0))

        form = ttk.LabelFrame(self, text="Input")
        form.grid(row=1, column=0, sticky="ew", pady=(16, 0))
        form.columnconfigure(0, weight=1)

        entry_row = ttk.Frame(form)
        entry_row.grid(row=0, column=0, sticky="ew", padx=10, pady=10)
        entry_row.columnconfigure(0, weight=1)

        self._entry = ttk.Entry(entry_row, textvariable=self._password_var, show="•")
        self._entry.grid(row=0, column=0, sticky="ew")
        self._entry.bind("<Return>", lambda _e: self.check_password())

        show_btn = ttk.Checkbutton(
            entry_row,
            text="Show",
            variable=self._show_var,
            command=self._toggle_show,
        )
        show_btn.grid(row=0, column=1, padx=(10, 0))

        buttons = ttk.Frame(form)
        buttons.grid(row=1, column=0, sticky="w", padx=10, pady=(0, 10))

        ttk.Button(buttons, text="Check Password", command=self.check_password).grid(row=0, column=0)
        ttk.Button(buttons, text="Generate Strong Password", command=self.generate_strong_password).grid(
            row=0, column=1, padx=(10, 0)
        )
        ttk.Button(buttons, text="Generate Passphrase", command=self.generate_passphrase).grid(
            row=0, column=2, padx=(10, 0)
        )
        ttk.Button(buttons, text="Clear", command=self.clear).grid(row=0, column=3, padx=(10, 0))

        hash_box = ttk.LabelFrame(self, text="Hash & Store (recommended for saving passwords)")
        hash_box.grid(row=2, column=0, sticky="ew", pady=(16, 0))
        hash_box.columnconfigure(0, weight=1)

        hash_top = ttk.Frame(hash_box)
        hash_top.grid(row=0, column=0, sticky="ew", padx=10, pady=10)
        hash_top.columnconfigure(1, weight=1)

        ttk.Label(hash_top, text="Label").grid(row=0, column=0, sticky="w")
        ttk.Entry(hash_top, textvariable=self._hash_label_var, width=18).grid(row=0, column=1, sticky="w", padx=(8, 0))
        ttk.Button(hash_top, text="Hash & Save", command=self.hash_and_save).grid(row=0, column=2, padx=(12, 0))
        ttk.Button(hash_top, text="Refresh History", command=self.refresh_hash_history).grid(row=0, column=3, padx=(8, 0))

        ttk.Label(hash_box, textvariable=self._hash_output_var, style="Subtle.TLabel").grid(
            row=1, column=0, sticky="w", padx=10, pady=(0, 6)
        )

        self._hash_history = tk.Text(hash_box, wrap="none", height=6, font=("TkDefaultFont", 10))
        self._hash_history.grid(row=2, column=0, sticky="ew", padx=10, pady=(0, 10))
        self._hash_history.configure(state="disabled")

        results = ttk.LabelFrame(self, text="Results")
        results.grid(row=3, column=0, sticky="nsew", pady=(16, 0))
        results.columnconfigure(0, weight=1)
        results.rowconfigure(3, weight=1)
        results.rowconfigure(0, weight=0)
        results.rowconfigure(1, weight=0)
        results.rowconfigure(2, weight=0)

        top = ttk.Frame(results)
        top.grid(row=0, column=0, sticky="ew", padx=10, pady=(10, 0))
        top.columnconfigure(0, weight=1)
        ttk.Label(top, textvariable=self._strength_var, font=("TkDefaultFont", 12, "bold")).grid(
            row=0, column=0, sticky="w"
        )
        ttk.Label(top, textvariable=self._score_var, style="Subtle.TLabel").grid(row=0, column=1, sticky="e")

        self._progress = ttk.Progressbar(
            results,
            maximum=100,
            variable=self._progress_var,
            mode="determinate",
            style="Weak.Horizontal.TProgressbar",
        )
        self._progress.grid(row=1, column=0, sticky="ew", padx=10, pady=(10, 0))

        hint = "Feedback"
        if self._common_loaded_count == 0:
            hint += " (common-password list file not loaded)"
        ttk.Label(results, text=hint, style="Subtle.TLabel").grid(row=2, column=0, sticky="w", padx=10, pady=(10, 6))

        text_frame = ttk.Frame(results)
        text_frame.grid(row=3, column=0, sticky="nsew", padx=10, pady=(0, 10))
        text_frame.columnconfigure(0, weight=1)
        text_frame.rowconfigure(0, weight=1)

        self._feedback_text = tk.Text(
            text_frame,
            wrap="word",
            height=10,
            font=("TkDefaultFont", 11),
            padx=10,
            pady=10,
        )
        self._feedback_text.grid(row=0, column=0, sticky="nsew")
        self._feedback_text.configure(state="disabled")

        scrollbar = ttk.Scrollbar(text_frame, orient="vertical", command=self._feedback_text.yview)
        scrollbar.grid(row=0, column=1, sticky="ns")
        self._feedback_text.configure(yscrollcommand=scrollbar.set)

        self._set_feedback("Enter a password above, then click “Check Password”.")
        self.refresh_hash_history()
        self._entry.focus_set()

    def _toggle_show(self) -> None:
        self._entry.configure(show="" if self._show_var.get() else "•")

    def _set_feedback(self, text: str) -> None:
        self._feedback_text.configure(state="normal")
        self._feedback_text.delete("1.0", "end")
        self._feedback_text.insert("1.0", text.strip() + "\n")
        self._feedback_text.configure(state="disabled")

    def _apply_score_to_ui(self, score: ScoreBreakdown) -> None:
        self._progress_var.set(score.score_0_100)
        self._strength_var.set(f"Strength: {score.strength_label}")
        self._score_var.set(f"Score: {score.score_0_100}/100")

        if score.strength_label == "Weak":
            self._progress.configure(style="Weak.Horizontal.TProgressbar")
        elif score.strength_label == "Moderate":
            self._progress.configure(style="Moderate.Horizontal.TProgressbar")
        else:
            self._progress.configure(style="Strong.Horizontal.TProgressbar")

    def check_password(self) -> None:
        pwd = self._password_var.get()
        patterns = detect_patterns(pwd)
        common = is_common_password(pwd, self._common_checker) if self._common_loaded_count else False
        penalty = compute_penalty_points(is_common_password=common, patterns=patterns)
        score = score_password(pwd, penalty_points=penalty)

        fb = generate_feedback(
            password=pwd,
            score=score,
            patterns=patterns,
            is_common_password=common,
            common_list_loaded_count=self._common_loaded_count,
        )

        self._apply_score_to_ui(score)
        lines = [fb.title, ""]
        for b in fb.bullets:
            lines.append(f"• {b}")
        self._set_feedback("\n".join(lines))

    def generate_strong_password(self) -> None:
        pwd = generate_random_password(MIN_PASSWORD_LENGTH)
        self._password_var.set(pwd)
        self._show_var.set(True)
        self._toggle_show()
        self.check_password()

    def generate_passphrase(self) -> None:
        pwd = generate_passphrase(3)
        self._password_var.set(pwd)
        self._show_var.set(True)
        self._toggle_show()
        self.check_password()

    def clear(self) -> None:
        self._password_var.set("")
        self._show_var.set(False)
        self._toggle_show()
        self._progress_var.set(0)
        self._strength_var.set("Strength: —")
        self._score_var.set("Score: —")
        self._hash_output_var.set("Hash: —")
        self._set_feedback("Enter a password above, then click “Check Password”.")
        self._entry.focus_set()

    def hash_and_save(self) -> None:
        pwd = self._password_var.get()
        if not pwd:
            messagebox.showwarning("Missing password", "Enter a password first.")
            return
        if len(pwd) < MIN_PASSWORD_LENGTH:
            messagebox.showwarning(
                "Password too short",
                f"Password must be at least {MIN_PASSWORD_LENGTH} characters to meet the policy.",
            )
            return

        ph = hash_password_pbkdf2(pwd)
        compact = ph.to_compact_string()
        row_id = save_password_hash(label=self._hash_label_var.get(), hash_string=compact)
        self._hash_output_var.set(f"Hash saved (id={row_id}): {compact}")
        self.refresh_hash_history()

    def refresh_hash_history(self) -> None:
        rows = list_password_hashes(limit=10)
        if not rows:
            text = "No saved hashes yet.\n"
        else:
            lines = ["Last saved hashes (most recent first):"]
            for r in rows:
                lines.append(f"- {r.id} | {r.created_at} | {r.label} | {r.hash_string}")
            text = "\n".join(lines) + "\n"

        self._hash_history.configure(state="normal")
        self._hash_history.delete("1.0", "end")
        self._hash_history.insert("1.0", text)
        self._hash_history.configure(state="disabled")


def run_app() -> None:
    root = tk.Tk()
    PasswordStrengthApp(root)
    try:
        # macOS sometimes launches the window behind other apps until clicked.
        root.update_idletasks()
        root.deiconify()
        root.lift()
        root.focus_force()
        root.attributes("-topmost", True)
        root.after(300, lambda: root.attributes("-topmost", False))
    except tk.TclError:
        pass
    root.mainloop()

