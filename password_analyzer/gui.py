from __future__ import annotations

import re
import sys
import tkinter as tk
from tkinter import messagebox

import customtkinter as ctk

from .analysis import compute_penalty_points, detect_patterns
from .common_passwords import is_common_password, load_common_passwords_checker
from .crypto import decrypt_password_vault_local, delete_vault_key_file, encrypt_password_vault_local, hash_password_pbkdf2
from .feedback import generate_feedback
from .generator import generate_random_password
from .policy import MIN_PASSWORD_LENGTH
from .scoring import ScoreBreakdown, score_password
from .storage import clear_vault_entries, get_vault_entry, list_password_hashes, save_password_hash

_RE_UPPER = re.compile(r"[A-Z]")
_RE_SYMBOL = re.compile(r"[^A-Za-z0-9]")

# Light theme palette (aligned with provided mockup)
_COLOR_BG = "#e8eef5"
_COLOR_CARD = "#ffffff"
_COLOR_NAVY = "#1e3a5f"
_COLOR_SUB = "#6b8cae"
_COLOR_MUTED = "#000000"
_COLOR_GREEN = "#16a34a"
_COLOR_BLUE = "#2563eb"
_COLOR_VAULT = "#eceaf5"
_COLOR_REC_BOX = "#dfe8f2"

# Default window fits this layout without a vertical scrollbar; smaller height shows the bar.
_DEFAULT_GEOMETRY = "920x760"


class PasswordStrengthApp(ctk.CTkFrame):
    def __init__(self, master: ctk.CTk) -> None:
        super().__init__(master, fg_color="transparent")
        self.master = master

        self._common_checker, common_meta = load_common_passwords_checker()
        self._common_loaded_count = common_meta.loaded_count

        self._password_var = tk.StringVar()
        self._show_var = tk.BooleanVar(value=False)
        self._strength_var = tk.StringVar(value="—")
        self._score_num_var = tk.StringVar(value="—")
        self._hash_label_var = tk.StringVar(value="password")
        self._vault_status_var = tk.StringVar(value="")
        self._stat_len = tk.StringVar(value="—")
        self._stat_ent = tk.StringVar(value="—")
        self._stat_up = tk.StringVar(value="—")
        self._stat_sym = tk.StringVar(value="—")

        self._vault_row_ids: list[int] = []
        self._body_font = ctk.CTkFont(family=None, size=13)
        self._small_font = ctk.CTkFont(family=None, size=12)
        self._mono_font = ctk.CTkFont(family="Courier New", size=12)
        self._title_font = ctk.CTkFont(family=None, size=22, weight="bold")
        self._section_font = ctk.CTkFont(family=None, size=11, weight="bold")

        self._canvas: tk.Canvas | None = None
        self._vsb: tk.Scrollbar | None = None
        self._scroll_inner: ctk.CTkFrame | None = None

        self._build_ui()

    def _on_master_configure(self, event: tk.Event) -> None:
        if event.widget is not self.master:
            return
        self.after_idle(self._sync_main_scrollbar)

    def _sync_main_scrollbar(self, _event: object | None = None) -> None:
        """Show vertical scrollbar only when inner content is taller than the canvas."""
        if self._canvas is None or self._scroll_inner is None or self._vsb is None:
            return
        self.master.update_idletasks()
        try:
            cv_h = int(self._canvas.winfo_height())
            inner_h = int(self._scroll_inner.winfo_reqheight())
        except tk.TclError:
            return
        if cv_h < 40:
            self.after(80, self._sync_main_scrollbar)
            return
        if inner_h > cv_h + 2:
            self._vsb.grid(row=0, column=1, sticky="ns", pady=(10, 10))
            self._canvas.grid(row=0, column=0, sticky="nsew", padx=(18, 0), pady=10)
            self._canvas.configure(scrollregion=self._canvas.bbox("all"))
        else:
            self._vsb.grid_remove()
            self._canvas.grid(row=0, column=0, columnspan=2, sticky="nsew", padx=18, pady=10)
            self._canvas.yview_moveto(0)

    def _build_ui(self) -> None:
        self.master.title("Password Strength Analyzer and Encryption")
        self.master.minsize(760, 520)
        self.master.configure(fg_color=_COLOR_BG)

        self.grid(row=0, column=0, sticky="nsew")
        self.master.rowconfigure(0, weight=1)
        self.master.columnconfigure(0, weight=1)
        self.columnconfigure(0, weight=1)
        self.rowconfigure(0, weight=1)

        outer = ctk.CTkFrame(self, fg_color="transparent")
        outer.grid(row=0, column=0, sticky="nsew")
        outer.rowconfigure(0, weight=1)
        outer.columnconfigure(0, weight=1)
        outer.columnconfigure(1, minsize=0)

        self._canvas = tk.Canvas(
            outer,
            highlightthickness=0,
            borderwidth=0,
            bg=_COLOR_BG,
        )
        self._vsb = tk.Scrollbar(outer, orient="vertical", command=self._canvas.yview)
        self._canvas.configure(yscrollcommand=self._vsb.set)

        self._scroll_inner = ctk.CTkFrame(self._canvas, fg_color="transparent")
        inner_win = self._canvas.create_window((0, 0), window=self._scroll_inner, anchor="nw")

        def _on_inner_configure(_e: object | None = None) -> None:
            self._canvas.configure(scrollregion=self._canvas.bbox("all"))
            self._sync_main_scrollbar()

        def _on_canvas_configure(e: tk.Event) -> None:
            self._canvas.itemconfigure(inner_win, width=e.width)
            self._sync_main_scrollbar()

        self._scroll_inner.bind("<Configure>", _on_inner_configure)
        self._canvas.bind("<Configure>", _on_canvas_configure)

        self._canvas.grid(row=0, column=0, columnspan=2, sticky="nsew", padx=18, pady=10)

        scroll = self._scroll_inner
        scroll.columnconfigure(0, weight=1)

        # Header
        head = ctk.CTkFrame(scroll, fg_color="transparent")
        head.grid(row=0, column=0, sticky="ew", pady=(0, 4))
        ctk.CTkLabel(
            head,
            text="Password Strength Analyzer and Encryption",
            font=self._title_font,
            text_color=_COLOR_NAVY,
            anchor="w",
        ).pack(anchor="w")
        ctk.CTkLabel(
            head,
            text="// analyze · generate · store securely",
            font=self._mono_font,
            text_color="#000000",  # dark black color
            anchor="w",
        ).pack(anchor="w", pady=(2, 0))
   

        # Password input
        ctk.CTkLabel(
            scroll,
            text="PASSWORD INPUT",
            font=self._section_font,
            text_color=_COLOR_MUTED,
            anchor="w",
        ).grid(row=1, column=0, sticky="w", pady=(10, 4))

        input_card = ctk.CTkFrame(scroll, fg_color=_COLOR_CARD, corner_radius=14)
        input_card.grid(row=2, column=0, sticky="ew", pady=(0, 2))
        input_card.columnconfigure(0, weight=1)

        entry_row = ctk.CTkFrame(input_card, fg_color="transparent")
        entry_row.grid(row=0, column=0, sticky="ew", padx=14, pady=(12, 8))
        entry_row.columnconfigure(0, weight=1)

        self._entry = ctk.CTkEntry(
            entry_row,
            textvariable=self._password_var,
            show="•",
            height=38,
            corner_radius=12,
            border_width=1,
            font=self._body_font,
            placeholder_text="Enter password…",
        )
        self._entry.grid(row=0, column=0, sticky="ew")
        self._entry.bind("<Return>", lambda _e: self.check_password())

        show_btn = ctk.CTkButton(
            entry_row,
            text="SHOW",
            width=80,
            height=32,
            corner_radius=10,
            font=ctk.CTkFont(size=12, weight="bold"),
            fg_color="#dbeafe",
            text_color=_COLOR_BLUE,
            hover_color="#bfdbfe",
            command=self._toggle_show_click,
        )
        show_btn.grid(row=0, column=1, padx=(12, 0))

        btns = ctk.CTkFrame(input_card, fg_color="transparent")
        btns.grid(row=1, column=0, sticky="ew", padx=14, pady=(0, 12))
        for c in range(3):
            btns.columnconfigure(c, weight=1)

        ctk.CTkButton(
            btns,
            text="Check password",
            height=34,
            corner_radius=12,
            font=self._small_font,
            fg_color=_COLOR_BLUE,
            hover_color="#1d4ed8",
            command=self.check_password,
        ).grid(row=0, column=0, sticky="ew", padx=(0, 6))
        ctk.CTkButton(
            btns,
            text="Generate strong password",
            height=34,
            corner_radius=12,
            font=self._small_font,
            fg_color="#f1f5f9",
            text_color=_COLOR_NAVY,
            hover_color="#e2e8f0",
            border_width=1,
            border_color="#cbd5e1",
            command=self.generate_strong_password,
        ).grid(row=0, column=1, sticky="ew", padx=6)
        ctk.CTkButton(
            btns,
            text="Clear",
            height=34,
            corner_radius=12,
            font=self._small_font,
            fg_color="#f1f5f9",
            text_color=_COLOR_NAVY,
            hover_color="#e2e8f0",
            border_width=1,
            border_color="#cbd5e1",
            command=self.clear,
        ).grid(row=0, column=2, sticky="ew", padx=(6, 0))

        # Strength card
        ctk.CTkLabel(
            scroll,
            text="STRENGTH ANALYSIS",
            font=self._section_font,
            text_color=_COLOR_MUTED,
            anchor="w",
        ).grid(row=3, column=0, sticky="w", pady=(10, 4))

        self._strength_card = ctk.CTkFrame(scroll, fg_color=_COLOR_CARD, corner_radius=16, border_width=1, border_color="#c7d7ea")
        self._strength_card.grid(row=4, column=0, sticky="ew")
        self._strength_card.columnconfigure(0, weight=1)

        top = ctk.CTkFrame(self._strength_card, fg_color="transparent")
        top.grid(row=0, column=0, sticky="ew", padx=14, pady=(10, 6))
        top.columnconfigure(1, weight=1)

        self._dot_label = ctk.CTkLabel(top, text="●", font=ctk.CTkFont(size=16), text_color="#94a3b8")
        self._dot_label.grid(row=0, column=0, sticky="w")
        ctk.CTkLabel(
            top,
            textvariable=self._strength_var,
            font=ctk.CTkFont(size=17, weight="bold"),
            text_color=_COLOR_NAVY,
        ).grid(row=0, column=1, sticky="w", padx=(6, 0))
        ctk.CTkLabel(
            top,
            textvariable=self._score_num_var,
            font=ctk.CTkFont(size=15, weight="bold"),
            text_color=_COLOR_SUB,
        ).grid(row=0, column=2, sticky="e")

        self._progress = ctk.CTkProgressBar(
            self._strength_card,
            height=14,
            corner_radius=7,
            progress_color="#94a3b8",
            fg_color="#e2e8f0",
        )
        self._progress.grid(row=1, column=0, sticky="ew", padx=14, pady=(0, 8))
        self._progress.set(0)

        grid_fr = ctk.CTkFrame(self._strength_card, fg_color="#f8fafc", corner_radius=12)
        grid_fr.grid(row=2, column=0, sticky="ew", padx=14, pady=(0, 8))
        for col in range(4):
            grid_fr.columnconfigure(col, weight=1)

        def _cell(parent: ctk.CTkFrame, r: int, c: int, title: str, var: tk.StringVar) -> None:
            f = ctk.CTkFrame(parent, fg_color="transparent")
            f.grid(row=r, column=c, sticky="nsew", padx=6, pady=6)
            ctk.CTkLabel(f, text=title, font=ctk.CTkFont(size=11), text_color=_COLOR_MUTED).pack(anchor="w")
            ctk.CTkLabel(f, textvariable=var, font=ctk.CTkFont(size=14, weight="bold"), text_color=_COLOR_GREEN).pack(anchor="w", pady=(4, 0))

        _cell(grid_fr, 0, 0, "LENGTH", self._stat_len)
        _cell(grid_fr, 0, 1, "ENTROPY", self._stat_ent)
        _cell(grid_fr, 0, 2, "UPPERCASE", self._stat_up)
        _cell(grid_fr, 0, 3, "SYMBOLS", self._stat_sym)

        sep = ctk.CTkFrame(self._strength_card, fg_color="#e2e8f0", height=1)
        sep.grid(row=3, column=0, sticky="ew", padx=14)

        hint = "Factual output from the analyzer (score, list checks, pattern flags)."
        if self._common_loaded_count == 0:
            hint += " Common-password file not loaded."
        ctk.CTkLabel(
            self._strength_card,
            text=hint,
            font=ctk.CTkFont(size=11),
            text_color=_COLOR_MUTED,
            anchor="w",
            justify="left",
        ).grid(row=4, column=0, sticky="w", padx=14, pady=(6, 2))

        self._results_text = ctk.CTkTextbox(
            self._strength_card,
            height=88,
            corner_radius=12,
            font=self._small_font,
            fg_color="#fafbfc",
            border_color="#e2e8f0",
            border_width=1,
            text_color=_COLOR_NAVY,
        )
        self._results_text.grid(row=5, column=0, sticky="ew", padx=14, pady=(0, 10))
        self._results_text.configure(state="disabled")

        # Recommendations
        ctk.CTkLabel(
            scroll,
            text="RECOMMENDATIONS",
            font=self._section_font,
            text_color=_COLOR_MUTED,
            anchor="w",
        ).grid(row=5, column=0, sticky="w", pady=(8, 4))

        rec_box = ctk.CTkFrame(scroll, fg_color=_COLOR_REC_BOX, corner_radius=14)
        rec_box.grid(row=6, column=0, sticky="ew")
        rec_box.columnconfigure(0, weight=1)

        self._rec_text = ctk.CTkTextbox(
            rec_box,
            height=72,
            corner_radius=12,
            font=self._small_font,
            fg_color="#f0f6fb",
            border_width=0,
            text_color=_COLOR_NAVY,
        )
        self._rec_text.grid(row=0, column=0, sticky="ew", padx=12, pady=10)
        self._rec_text.configure(state="disabled")

        # Vault
        ctk.CTkLabel(
            scroll,
            text="SECURE STORAGE (SQLite + PBKDF2)",
            font=self._section_font,
            text_color=_COLOR_MUTED,
            anchor="w",
        ).grid(row=7, column=0, sticky="w", pady=(8, 4))

        vault = ctk.CTkFrame(scroll, fg_color=_COLOR_VAULT, corner_radius=16, border_width=1, border_color="#d4d0e8")
        vault.grid(row=8, column=0, sticky="ew", pady=(0, 8))
        vault.columnconfigure(0, weight=1)

        vhead = ctk.CTkFrame(vault, fg_color="transparent")
        vhead.grid(row=0, column=0, sticky="ew", padx=14, pady=(10, 4))
        vhead.columnconfigure(0, weight=1)
        ctk.CTkLabel(vhead, text="Save in Database", font=ctk.CTkFont(size=15, weight="bold"), text_color=_COLOR_NAVY).grid(
            row=0, column=0, sticky="w"
        )
        ctk.CTkLabel(
            vhead,
            text="ENCRYPTED",
            font=ctk.CTkFont(size=11, weight="bold"),
            text_color=_COLOR_GREEN,
            fg_color="#dcfce7",
            corner_radius=8,
            padx=10,
            pady=4,
        ).grid(row=0, column=1, sticky="e")

        ctk.CTkLabel(vault, text="Password Label", font=self._small_font, text_color=_COLOR_MUTED, anchor="w").grid(
            row=1, column=0, sticky="w", padx=14, pady=(2, 2)
        )
        ctk.CTkEntry(
            vault,
            textvariable=self._hash_label_var,
            height=36,
            corner_radius=12,
            placeholder_text="e.g. Wi‑Fi",
            font=self._body_font,
        ).grid(row=2, column=0, sticky="ew", padx=14, pady=(0, 8))

        vb = ctk.CTkFrame(vault, fg_color="transparent")
        vb.grid(row=3, column=0, sticky="ew", padx=14, pady=(0, 6))
        for i in range(4):
            vb.columnconfigure(i, weight=1)

        ctk.CTkButton(
            vb,
            text="Hash + encrypt & save",
            height=34,
            corner_radius=12,
            font=self._small_font,
            fg_color=_COLOR_BLUE,
            hover_color="#1d4ed8",
            command=self.hash_encrypt_and_save,
        ).grid(row=0, column=0, sticky="ew", padx=(0, 6))
        ctk.CTkButton(
            vb,
            text="Refresh list",
            height=34,
            corner_radius=12,
            font=self._small_font,
            fg_color="#f1f5f9",
            text_color=_COLOR_NAVY,
            hover_color="#e2e8f0",
            border_width=1,
            border_color="#cbd5e1",
            command=self.refresh_vault_list,
        ).grid(row=0, column=1, sticky="ew", padx=6)
        ctk.CTkButton(
            vb,
            text="Restore Selected Password",
            height=34,
            corner_radius=12,
            font=self._small_font,
            fg_color="#f1f5f9",
            text_color=_COLOR_NAVY,
            hover_color="#e2e8f0",
            border_width=1,
            border_color="#cbd5e1",
            command=self.restore_selected,
        ).grid(row=0, column=2, sticky="ew", padx=6)
        ctk.CTkButton(
            vb,
            text="Clear Database",
            height=34,
            corner_radius=12,
            font=self._small_font,
            fg_color="#fef2f2",
            text_color="#b91c1c",
            hover_color="#fecaca",
            border_width=1,
            border_color="#fecaca",
            command=self.clear_vault_confirm,
        ).grid(row=0, column=3, sticky="ew", padx=(6, 0))

        ctk.CTkLabel(vault, textvariable=self._vault_status_var, font=ctk.CTkFont(size=11), text_color=_COLOR_SUB, anchor="w").grid(
            row=4, column=0, sticky="w", padx=14, pady=(2, 4)
        )

        list_fr = ctk.CTkFrame(vault, fg_color=_COLOR_CARD, corner_radius=12)
        list_fr.grid(row=5, column=0, sticky="ew", padx=14, pady=(2, 12))
        list_fr.columnconfigure(0, weight=1)

        self._vault_list = tk.Listbox(
            list_fr,
            height=5,
            font=("Segoe UI", 11),
            bg="#ffffff",
            fg=_COLOR_NAVY,
            selectbackground="#dbeafe",
            selectforeground=_COLOR_NAVY,
            highlightthickness=0,
            borderwidth=0,
            activestyle="none",
        )
        self._vault_list.grid(row=0, column=0, sticky="ew", padx=8, pady=8)
        vsb = tk.Scrollbar(list_fr, orient="vertical", command=self._vault_list.yview)
        vsb.grid(row=0, column=1, sticky="ns", pady=8)
        self._vault_list.configure(yscrollcommand=vsb.set)

        self._set_results_and_recs_empty()
        self._reset_strength_card()
        self.refresh_vault_list()
        self._entry.focus_set()

        self.master.bind("<Configure>", self._on_master_configure, add="+")

        def _wheel(event: tk.Event) -> None:
            if self._canvas is None or self._vsb is None or not self._vsb.winfo_ismapped():
                return
            if sys.platform == "darwin":
                self._canvas.yview_scroll(int(-event.delta), "units")
            else:
                d = int(getattr(event, "delta", 0) or 0)
                if d:
                    self._canvas.yview_scroll(int(-d / 120), "units")
                elif getattr(event, "num", 0) == 4:
                    self._canvas.yview_scroll(-1, "units")
                elif getattr(event, "num", 0) == 5:
                    self._canvas.yview_scroll(1, "units")

        self._canvas.bind("<MouseWheel>", _wheel)
        self._scroll_inner.bind("<MouseWheel>", _wheel)
        self._canvas.bind("<Button-4>", _wheel)
        self._canvas.bind("<Button-5>", _wheel)

        self.master.after_idle(self._sync_main_scrollbar)

    def _toggle_show_click(self) -> None:
        self._show_var.set(not self._show_var.get())
        self._entry.configure(show="" if self._show_var.get() else "•")

    def _reset_strength_card(self) -> None:
        self._progress.set(0)
        self._strength_var.set("—")
        self._score_num_var.set("—")
        self._dot_label.configure(text_color="#94a3b8")
        self._progress.configure(progress_color="#94a3b8")
        self._stat_len.set("—")
        self._stat_ent.set("—")
        self._stat_up.set("—")
        self._stat_sym.set("—")

    def _set_text_widget(self, widget: ctk.CTkTextbox, text: str) -> None:
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.insert("1.0", text.strip() + "\n")
        widget.configure(state="disabled")

    def _set_results_and_recs_empty(self) -> None:
        self._set_text_widget(self._results_text, "Enter a password and click “Check password”.")
        self._set_text_widget(self._rec_text, "Recommendations will appear here after analysis.")

    def _pwd_stats(self, pwd: str, score: ScoreBreakdown) -> None:
        if not pwd:
            self._stat_len.set("—")
            self._stat_ent.set("—")
            self._stat_up.set("—")
            self._stat_sym.set("—")
            return
        self._stat_len.set(f"{len(pwd)} chars")
        self._stat_ent.set(f"{score.estimated_entropy_bits:.0f} bits")
        self._stat_up.set("✓ yes" if _RE_UPPER.search(pwd) else "no")
        self._stat_sym.set("✓ yes" if _RE_SYMBOL.search(pwd) else "no")

    def _apply_score_to_ui(self, score: ScoreBreakdown, pwd: str) -> None:
        pct = score.score_0_100 / 100.0
        self._progress.set(pct)
        self._strength_var.set(score.strength_label)
        self._score_num_var.set(f"{score.score_0_100} / 100")

        if score.strength_label == "Weak":
            col = "#ef4444"
        elif score.strength_label == "Moderate":
            col = "#f97316"
        else:
            col = _COLOR_GREEN
        self._dot_label.configure(text_color=col)
        self._progress.configure(progress_color=col)
        self._pwd_stats(pwd, score)

    def check_password(self) -> None:
        pwd = self._password_var.get()
        patterns = detect_patterns(pwd)
        common = is_common_password(pwd, self._common_checker) if self._common_loaded_count else False
        penalty = compute_penalty_points(password=pwd, is_common_password=common, patterns=patterns)
        score = score_password(pwd, penalty_points=penalty)

        fb = generate_feedback(
            password=pwd,
            score=score,
            patterns=patterns,
            is_common_password=common,
            common_list_loaded_count=self._common_loaded_count,
        )

        self._apply_score_to_ui(score, pwd)
        res_lines = [fb.results_title, ""] + [f"• {line}" for line in fb.results]
        rec_lines = [f"• {line}" for line in fb.recommendations] if fb.recommendations else ["• No extra recommendations."]
        self._set_text_widget(self._results_text, "\n".join(res_lines))
        self._set_text_widget(self._rec_text, "\n".join(rec_lines))

    def generate_strong_password(self) -> None:
        pwd = generate_random_password(MIN_PASSWORD_LENGTH)
        self._password_var.set(pwd)
        self._show_var.set(True)
        self._entry.configure(show="")
        self.check_password()

    def clear(self) -> None:
        self._password_var.set("")
        self._show_var.set(False)
        self._entry.configure(show="•")
        self._vault_status_var.set("")
        self._reset_strength_card()
        self._set_results_and_recs_empty()
        self._entry.focus_set()

    def hash_encrypt_and_save(self) -> None:
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

        try:
            enc = encrypt_password_vault_local(pwd)
        except ValueError as e:
            messagebox.showerror("Encryption failed", str(e))
            return

        ph = hash_password_pbkdf2(pwd)
        compact = ph.to_compact_string()
        row_id = save_password_hash(label=self._hash_label_var.get(), hash_string=compact, enc_payload=enc)
        self._vault_status_var.set(
            f"Saved entry #{row_id}: PBKDF2 hash stored; password encrypted with AES-256-GCM on this device (restorable)."
        )
        self.refresh_vault_list()

    def refresh_vault_list(self) -> None:
        rows = list_password_hashes(limit=50)
        self._vault_list.delete(0, "end")
        self._vault_row_ids = []
        if not rows:
            self._vault_list.insert("end", " (no saved entries yet)")
            return
        for r in rows:
            self._vault_row_ids.append(r.id)
            tag = "restorable" if r.enc_payload else "hash-only"
            line = f"#{r.id}  |  {r.label}  |  {r.created_at}  |  {tag}"
            self._vault_list.insert("end", line)

    def clear_vault_confirm(self) -> None:
        if not messagebox.askyesno(
            "Clear Database",
            "Delete all saved vault rows and the local encryption key file?\n\n"
            "Use this for testing; saved passwords cannot be recovered after this.",
        ):
            return
        n = clear_vault_entries()
        delete_vault_key_file()
        self._vault_row_ids = []
        self._vault_status_var.set(f"Cleared {n} row(s). New saves will use a fresh encryption key.")
        self.refresh_vault_list()

    def restore_selected(self) -> None:
        if not self._vault_row_ids:
            messagebox.showinfo("Nothing to restore", "Save an entry with “Hash + encrypt & save” first.")
            return
        sel = self._vault_list.curselection()
        if not sel:
            messagebox.showinfo("Select an entry", "Click a row in the list, then press Restore Selected Password.")
            return
        idx = int(sel[0])
        if idx < 0 or idx >= len(self._vault_row_ids):
            messagebox.showwarning("Invalid selection", "Choose a saved entry from the list.")
            return

        row_id = self._vault_row_ids[idx]
        entry = get_vault_entry(row_id=row_id)
        if not entry:
            messagebox.showerror("Not found", "That entry could not be loaded.")
            return
        if not entry.enc_payload:
            messagebox.showinfo(
                "Cannot restore",
                "This row only has a one-way hash (no encrypted copy). Save again with “Hash + encrypt & save”.",
            )
            return

        try:
            plain = decrypt_password_vault_local(entry.enc_payload)
        except Exception:
            messagebox.showerror(
                "Restore failed",
                "Could not decrypt this row. It may be from an older build (master password). Clear the vault and save again.",
            )
            return

        self._password_var.set(plain)
        self._show_var.set(True)
        self._entry.configure(show="")
        self._vault_status_var.set(f"Restored entry #{row_id} into the password field (not copied to clipboard).")
        self.check_password()


def run_app() -> None:
    ctk.set_appearance_mode("Light")
    ctk.set_default_color_theme("blue")

    root = ctk.CTk()
    root.geometry(_DEFAULT_GEOMETRY)
    PasswordStrengthApp(root)
    try:
        root.update_idletasks()
        root.deiconify()
        root.lift()
        root.focus_force()
        root.attributes("-topmost", True)
        root.after(300, lambda: root.attributes("-topmost", False))
    except tk.TclError:
        pass
    root.mainloop()
