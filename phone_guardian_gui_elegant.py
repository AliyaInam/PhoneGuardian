"""
Phone Guardian — Elegant Tkinter dashboard

Design philosophy: dark graphite security console, cyan safe-state accents,
amber caution states, red danger states, generous spacing, and clear report
hierarchy. This file is only the interface; phone_guardian.py remains the
scanner engine.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox


APP_BG = "#0b1118"
PANEL = "#121c26"
PANEL_2 = "#172431"
BORDER = "#263848"
TEXT = "#e6f0f5"
MUTED = "#8fa5b2"
CYAN = "#43d9e8"
CYAN_DARK = "#123e49"
GREEN = "#47d7a0"
AMBER = "#f4b942"
RED = "#ff6b6b"
WHITE = "#ffffff"


class PhoneGuardianApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("Phone Guardian | Defensive File Analyzer")
        self.geometry("940x680")
        self.minsize(780, 560)
        self.configure(bg=APP_BG)

        self.base_dir = Path(__file__).resolve().parent
        self.scanner_path = self.base_dir / "phone_guardian.py"
        self.selected_file: Path | None = None
        self.report_path = self.base_dir / "phone_guardian_report.json"
        self.last_report: dict = {}

        self._build_styles()
        self._build_header()
        self._build_main()
        self._build_footer()

    def _build_styles(self) -> None:
        self.option_add("*Font", "Arial 10")
        self.option_add("*TButton.Cursor", "hand2")
        self.option_add("*TEntry.Background", PANEL_2)
        self.option_add("*TEntry.Foreground", TEXT)

    def _label(self, parent, text, size=10, color=TEXT, weight="normal"):
        return tk.Label(
            parent,
            text=text,
            bg=parent.cget("bg"),
            fg=color,
            font=("Arial", size, weight),
        )

    def _build_header(self) -> None:
        header = tk.Frame(self, bg=APP_BG)
        header.pack(fill="x", padx=34, pady=(28, 12))

        identity = tk.Frame(header, bg=APP_BG)
        identity.pack(side="left")
        tk.Label(
            identity,
            text="◈",
            bg=APP_BG,
            fg=CYAN,
            font=("Arial", 30, "bold"),
        ).pack(side="left", padx=(0, 12))
        words = tk.Frame(identity, bg=APP_BG)
        words.pack(side="left")
        tk.Label(
            words,
            text="PHONE GUARDIAN // DESKTOP",
            bg=APP_BG,
            fg=CYAN,
            font=("Arial", 9, "bold"),
        ).pack(anchor="w")
        tk.Label(
            words,
            text="Defensive File Analyzer",
            bg=APP_BG,
            fg=TEXT,
            font=("Arial", 22, "bold"),
        ).pack(anchor="w")

        status = tk.Frame(header, bg=APP_BG)
        status.pack(side="right", anchor="center")
        tk.Label(status, text="●", bg=APP_BG, fg=GREEN, font=("Arial", 12)).pack(side="left")
        tk.Label(
            status,
            text="LOCAL ENGINE READY",
            bg=APP_BG,
            fg=MUTED,
            font=("Arial", 9, "bold"),
        ).pack(side="left", padx=(7, 0))

        tk.Frame(self, bg=CYAN, height=1).pack(fill="x", padx=34)

    def _build_main(self) -> None:
        body = tk.Frame(self, bg=APP_BG)
        body.pack(fill="both", expand=True, padx=34, pady=22)
        body.columnconfigure(0, weight=3)
        body.columnconfigure(1, weight=2)
        body.rowconfigure(1, weight=1)

        self._build_file_card(body)
        self._build_result_card(body)
        self._build_report_card(body)

    def _card(self, parent, row, column, title: str):
        frame = tk.Frame(parent, bg=PANEL, highlightbackground=BORDER, highlightthickness=1)
        frame.grid(row=row, column=column, sticky="nsew", padx=(0 if column == 0 else 12, 12 if column == 0 else 0), pady=(0, 14))
        frame.columnconfigure(0, weight=1)
        tk.Label(
            frame,
            text=title.upper(),
            bg=PANEL,
            fg=MUTED,
            font=("Arial", 9, "bold"),
        ).grid(row=0, column=0, sticky="w", padx=20, pady=(18, 5))
        return frame

    def _build_file_card(self, parent) -> None:
        card = self._card(parent, 0, 0, "Select a file")
        card.grid_configure(columnspan=1)
        self.file_name = tk.Label(
            card,
            text="No file selected",
            bg=PANEL,
            fg=TEXT,
            anchor="w",
            font=("Arial", 14, "bold"),
        )
        self.file_name.grid(row=1, column=0, sticky="ew", padx=20, pady=(8, 4))
        self.file_meta = tk.Label(
            card,
            text="Choose a text file, document, or authorized APK to analyze.",
            bg=PANEL,
            fg=MUTED,
            anchor="w",
            justify="left",
            wraplength=470,
        )
        self.file_meta.grid(row=2, column=0, sticky="ew", padx=20, pady=(0, 18))

        controls = tk.Frame(card, bg=PANEL)
        controls.grid(row=3, column=0, sticky="ew", padx=20, pady=(0, 20))
        tk.Button(
            controls,
            text="CHOOSE FILE",
            command=self.choose_file,
            bg=CYAN_DARK,
            fg=CYAN,
            activebackground="#1c5662",
            activeforeground=WHITE,
            relief="flat",
            padx=18,
            pady=10,
            font=("Arial", 10, "bold"),
        ).pack(side="left")
        self.scan_button = tk.Button(
            controls,
            text="SCAN FILE",
            command=self.scan_file,
            state="disabled",
            bg=CYAN,
            fg="#071015",
            activebackground="#89f3fa",
            relief="flat",
            padx=22,
            pady=10,
            font=("Arial", 10, "bold"),
        )
        self.scan_button.pack(side="left", padx=(10, 0))
        tk.Button(
            controls,
            text="CLEAR",
            command=self.clear_all,
            bg=PANEL_2,
            fg=MUTED,
            activebackground=BORDER,
            activeforeground=TEXT,
            relief="flat",
            padx=18,
            pady=10,
            font=("Arial", 10, "bold"),
        ).pack(side="right")

    def _build_result_card(self, parent) -> None:
        card = self._card(parent, 0, 1, "Risk assessment")
        card.grid_configure(sticky="nsew")
        self.risk_badge = tk.Label(
            card,
            text="READY",
            bg=CYAN_DARK,
            fg=CYAN,
            font=("Arial", 16, "bold"),
            padx=15,
            pady=10,
        )
        self.risk_badge.grid(row=1, column=0, sticky="w", padx=20, pady=(14, 10))
        self.score_label = tk.Label(card, text="Score  —", bg=PANEL, fg=TEXT, font=("Arial", 12, "bold"))
        self.score_label.grid(row=2, column=0, sticky="w", padx=20, pady=4)
        self.status_label = tk.Label(
            card,
            text="Select a file to begin.",
            bg=PANEL,
            fg=MUTED,
            justify="left",
            anchor="w",
            wraplength=250,
        )
        self.status_label.grid(row=3, column=0, sticky="ew", padx=20, pady=(4, 20))

    def _build_report_card(self, parent) -> None:
        card = self._card(parent, 1, 0, "Scan report")
        card.grid_configure(columnspan=2, padx=0)
        card.rowconfigure(1, weight=1)
        report_frame = tk.Frame(card, bg="#0a1016")
        report_frame.grid(row=1, column=0, sticky="nsew", padx=20, pady=(12, 14))
        report_frame.rowconfigure(0, weight=1)
        report_frame.columnconfigure(0, weight=1)
        self.report_text = tk.Text(
            report_frame,
            height=10,
            bg="#0a1016",
            fg="#b9d8df",
            insertbackground=CYAN,
            relief="flat",
            wrap="word",
            padx=14,
            pady=12,
            font=("Consolas", 10),
        )
        self.report_text.grid(row=0, column=0, sticky="nsew")
        self.report_text.insert("1.0", "Your scan report will appear here.\n\nThe scanner engine is ready for a safe defensive analysis.")
        self.report_text.configure(state="disabled")
        tk.Button(
            card,
            text="OPEN JSON REPORT",
            command=self.open_report,
            bg=PANEL_2,
            fg=CYAN,
            activebackground=BORDER,
            activeforeground=WHITE,
            relief="flat",
            padx=16,
            pady=8,
            font=("Arial", 9, "bold"),
        ).grid(row=2, column=0, sticky="e", padx=20, pady=(0, 18))

    def _build_footer(self) -> None:
        footer = tk.Frame(self, bg=APP_BG)
        footer.pack(fill="x", padx=34, pady=(0, 20))
        tk.Label(
            footer,
            text="SAFE MODE  •  ANALYZE ONLY FILES YOU OWN OR ARE AUTHORIZED TO REVIEW",
            bg=APP_BG,
            fg="#5d7784",
            font=("Arial", 8, "bold"),
        ).pack(side="left")
        self.progress_label = tk.Label(footer, text="IDLE", bg=APP_BG, fg=MUTED, font=("Arial", 8, "bold"))
        self.progress_label.pack(side="right")

    def choose_file(self) -> None:
        path = filedialog.askopenfilename(
            title="Choose a file to analyze",
            filetypes=[
                ("Supported files", "*.apk *.txt *.pdf *.docx *.zip *.*"),
                ("Android packages", "*.apk"),
                ("All files", "*.*"),
            ],
        )
        if not path:
            return
        self.selected_file = Path(path)
        size_kb = self.selected_file.stat().st_size / 1024
        self.file_name.configure(text=self.selected_file.name, fg=CYAN)
        self.file_meta.configure(text=f"{self.selected_file.suffix.upper() or 'FILE'}  •  {size_kb:,.1f} KB  •  Ready for analysis")
        self.scan_button.configure(state="normal")
        self.risk_badge.configure(text="READY", bg=CYAN_DARK, fg=CYAN)
        self.status_label.configure(text="File selected. Press SCAN FILE to begin.", fg=MUTED)
        self.progress_label.configure(text="FILE LOADED", fg=CYAN)

    def scan_file(self) -> None:
        if not self.selected_file:
            return
        if not self.scanner_path.exists():
            messagebox.showerror("Scanner not found", "Keep phone_guardian.py in the same folder as this GUI file.")
            return
        self.scan_button.configure(state="disabled", text="SCANNING...")
        self.progress_label.configure(text="ANALYZING", fg=AMBER)
        self.status_label.configure(text="The local scanner is analyzing the selected file...", fg=AMBER)
        threading.Thread(target=self._run_scan, daemon=True).start()

    def _run_scan(self) -> None:
        try:
            result = subprocess.run(
                [sys.executable, str(self.scanner_path), str(self.selected_file)],
                cwd=str(self.base_dir),
                capture_output=True,
                text=True,
                timeout=120,
            )
            output = (result.stdout or "") + ("\n" + result.stderr if result.stderr else "")
            report = {}
            if self.report_path.exists():
                try:
                    report = json.loads(self.report_path.read_text(encoding="utf-8"))
                except json.JSONDecodeError:
                    report = {}
            self.after(0, lambda: self._finish_scan(result.returncode, output, report))
        except Exception as exc:
            self.after(0, lambda: self._finish_scan(1, str(exc), {}))

    def _finish_scan(self, returncode: int, output: str, report: dict) -> None:
        self.scan_button.configure(state="normal", text="SCAN FILE")
        self.last_report = report
        if returncode != 0:
            self.risk_badge.configure(text="ERROR", bg="#4b2028", fg=RED)
            self.status_label.configure(text="The scanner returned an error. Read the report panel for details.", fg=RED)
            self.progress_label.configure(text="SCAN ERROR", fg=RED)
        else:
            risk = str(report.get("risk", "Low")).lower()
            score = report.get("score", 0)
            if "high" in risk:
                bg, fg = "#4b2028", RED
            elif "medium" in risk:
                bg, fg = "#4b3917", AMBER
            else:
                bg, fg = "#143b35", GREEN
            self.risk_badge.configure(text=f"{risk.upper()} RISK", bg=bg, fg=fg)
            self.score_label.configure(text=f"Score  {score}")
            self.status_label.configure(text="Analysis complete. Review the findings below.", fg=fg)
            self.progress_label.configure(text="SCAN COMPLETE", fg=fg)
        self._set_report_text(output, report)

    def _set_report_text(self, output: str, report: dict) -> None:
        lines = []
        if report:
            lines.append(json.dumps(report, indent=2, ensure_ascii=False))
        else:
            lines.append(output.strip())
        self.report_text.configure(state="normal")
        self.report_text.delete("1.0", "end")
        self.report_text.insert("1.0", "\n".join(lines) or "No report output was returned.")
        self.report_text.configure(state="disabled")

    def open_report(self) -> None:
        if not self.report_path.exists():
            messagebox.showinfo("Report not available", "Run a scan first. The JSON report will then appear here.")
            return
        try:
            os.startfile(self.report_path)  # type: ignore[attr-defined]
        except AttributeError:
            subprocess.Popen(["xdg-open", str(self.report_path)])

    def clear_all(self) -> None:
        self.selected_file = None
        self.file_name.configure(text="No file selected", fg=TEXT)
        self.file_meta.configure(text="Choose a text file, document, or authorized APK to analyze.")
        self.scan_button.configure(state="disabled", text="SCAN FILE")
        self.risk_badge.configure(text="READY", bg=CYAN_DARK, fg=CYAN)
        self.score_label.configure(text="Score  —")
        self.status_label.configure(text="Select a file to begin.", fg=MUTED)
        self.progress_label.configure(text="IDLE", fg=MUTED)
        self.report_text.configure(state="normal")
        self.report_text.delete("1.0", "end")
        self.report_text.insert("1.0", "Your scan report will appear here.\n\nThe scanner engine is ready for a safe defensive analysis.")
        self.report_text.configure(state="disabled")


if __name__ == "__main__":
    app = PhoneGuardianApp()
    app.mainloop()
