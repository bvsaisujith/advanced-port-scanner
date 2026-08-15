from __future__ import annotations

import threading
from datetime import datetime
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from src.reporting.pdf_report import PdfReportGenerator
from src.scanner.port_scanner import PortScanner
from src.scanner.target_parser import normalize_target, parse_ports
from src.utils.formatters import build_summary_text, format_result_line


class PortScannerApp:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("Port Scanner")
        self.root.geometry("820x560")

        self.scanner = PortScanner()
        self.report_generator = PdfReportGenerator()
        self.latest_session = None
        self.expected_results = 0

        self._build_ui()

    def _build_ui(self) -> None:
        container = ttk.Frame(self.root, padding=16)
        container.pack(fill="both", expand=True)

        form = ttk.Frame(container)
        form.pack(fill="x")

        ttk.Label(form, text="Target").grid(row=0, column=0, sticky="w")
        self.target_var = tk.StringVar(value="127.0.0.1")
        ttk.Entry(form, textvariable=self.target_var, width=32).grid(row=1, column=0, padx=(0, 12), pady=(4, 12), sticky="w")

        ttk.Label(form, text="Ports").grid(row=0, column=1, sticky="w")
        self.ports_var = tk.StringVar(value="")
        ttk.Entry(form, textvariable=self.ports_var, width=48).grid(row=1, column=1, pady=(4, 12), sticky="we")

        actions = ttk.Frame(container)
        actions.pack(fill="x", pady=(0, 12))

        self.scan_button = ttk.Button(actions, text="Start Scan", command=self.start_scan)
        self.scan_button.pack(side="left")

        self.demo_button = ttk.Button(actions, text="Quick Localhost Demo", command=self.quick_localhost_demo)
        self.demo_button.pack(side="left", padx=(8, 0))

        self.export_button = ttk.Button(actions, text="Export PDF", command=self.export_pdf, state="disabled")
        self.export_button.pack(side="left", padx=(8, 0))

        self.status_var = tk.StringVar(value="Ready")
        ttk.Label(actions, textvariable=self.status_var).pack(side="right")

        self.progress_var = tk.DoubleVar(value=0)
        self.progress_bar = ttk.Progressbar(container, maximum=100, variable=self.progress_var)
        self.progress_bar.pack(fill="x", pady=(0, 12))

        self.summary_text = tk.Text(container, height=5, wrap="word")
        self.summary_text.pack(fill="x", pady=(0, 12))
        self.summary_text.insert("1.0", "No scan yet.")
        self.summary_text.configure(state="disabled")

        table_frame = ttk.Frame(container)
        table_frame.pack(fill="both", expand=True)

        columns = ("port", "status", "time", "banner", "error")
        self.results_table = ttk.Treeview(table_frame, columns=columns, show="headings")
        self.results_table.heading("port", text="Port")
        self.results_table.heading("status", text="Status")
        self.results_table.heading("time", text="Response Time")
        self.results_table.heading("banner", text="Banner")
        self.results_table.heading("error", text="Error")

        self.results_table.column("port", width=70, anchor="center")
        self.results_table.column("status", width=90, anchor="center")
        self.results_table.column("time", width=110, anchor="center")
        self.results_table.column("banner", width=330)
        self.results_table.column("error", width=180)

        scrollbar = ttk.Scrollbar(table_frame, orient="vertical", command=self.results_table.yview)
        self.results_table.configure(yscrollcommand=scrollbar.set)
        self.results_table.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

    def quick_localhost_demo(self) -> None:
        self.target_var.set("127.0.0.1")
        self.ports_var.set("22,80,443,3389")
        self.start_scan()

    def start_scan(self) -> None:
        try:
            target = normalize_target(self.target_var.get())
            ports = parse_ports(self.ports_var.get())
        except ValueError as exc:
            messagebox.showerror("Invalid input", str(exc))
            return
        except Exception:
            messagebox.showerror("Invalid input", "Ports must be comma-separated values or ranges like 20-25.")
            return

        self.scan_button.configure(state="disabled")
        self.demo_button.configure(state="disabled")
        self.export_button.configure(state="disabled")
        self.expected_results = len(ports)
        self.progress_var.set(0)
        self.progress_bar.configure(maximum=max(1, self.expected_results))
        self.status_var.set("Scanning...")
        self._clear_results()

        thread = threading.Thread(target=self._run_scan, args=(target, ports), daemon=True)
        thread.start()

    def _run_scan(self, target: str, ports: list[int]) -> None:
        session = self.scanner.scan(target, ports, progress_callback=self._on_progress)
        self.latest_session = session
        self.root.after(0, lambda: self._show_session(session))

    def _on_progress(self, completed: int, total: int, result) -> None:
        self.root.after(0, lambda: self._update_progress(completed, total, result))

    def _update_progress(self, completed: int, total: int, result) -> None:
        self.progress_var.set(completed)
        state = "Open" if result.is_open else "Closed"
        self.status_var.set(f"Scanning... {completed}/{total} complete, last: port {result.port} {state}")
        self.results_table.insert(
            "",
            "end",
            values=(
                result.port,
                state,
                f"{result.response_time_ms:.2f} ms" if result.response_time_ms is not None else "-",
                result.banner or "",
                result.error or "",
            ),
        )

    def _show_session(self, session) -> None:
        self._update_summary(session)
        summary_line = build_summary_text(session)
        self.status_var.set(f"Done - {len(session.open_ports)} open ports")
        self.scan_button.configure(state="normal")
        self.demo_button.configure(state="normal")
        self.export_button.configure(state="normal")
        self.progress_var.set(self.expected_results)
        print(summary_line)
        for result in session.results:
            print(format_result_line(result.port, "Open" if result.is_open else "Closed", result.response_time_ms))

    def export_pdf(self) -> None:
        if self.latest_session is None:
            messagebox.showinfo("No scan", "Run a scan first.")
            return

        default_name = f"scan-report-{datetime.now().strftime('%Y%m%d-%H%M%S')}.pdf"
        output_path = filedialog.asksaveasfilename(
            title="Save PDF Report",
            defaultextension=".pdf",
            initialfile=default_name,
            filetypes=[("PDF files", "*.pdf")],
        )
        if not output_path:
            return

        saved_path = self.report_generator.generate(self.latest_session, Path(output_path))
        messagebox.showinfo("Report created", f"PDF saved to {saved_path}")

    def _clear_results(self) -> None:
        for item in self.results_table.get_children():
            self.results_table.delete(item)

    def _update_summary(self, session) -> None:
        text = build_summary_text(session)
        self.summary_text.configure(state="normal")
        self.summary_text.delete("1.0", tk.END)
        self.summary_text.insert("1.0", text)
        self.summary_text.configure(state="disabled")
