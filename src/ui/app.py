from __future__ import annotations

import threading
from datetime import datetime
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from src.reporting.pdf_report import PdfReportGenerator
from src.scanner.port_scanner import PortScanner
from src.scanner.target_parser import normalize_target, parse_ports, resolve_target
from src.utils.formatters import build_result_sections, build_summary_text, format_result_line


class PortScannerApp:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("Advanced Port Scanner")
        self.root.geometry("1000x700")

        self.scanner = None
        self.report_generator = PdfReportGenerator()
        self.latest_session = None
        self.current_dns_resolution = None
        self.expected_results = 0
        self.result_trees: dict[str, ttk.Treeview] = {}
        self.scan_stop_event = threading.Event()
        self.scan_thread: threading.Thread | None = None

        # Configuration variables
        self.scan_type_var = tk.StringVar(value="tcp_connect")
        self.os_detection_var = tk.BooleanVar(value=False)
        self.service_detection_var = tk.BooleanVar(value=True)
        self.vulnerability_scan_var = tk.BooleanVar(value=False)
        self.ai_enhancements_var = tk.BooleanVar(value=True)

        self._build_ui()

    def _build_ui(self) -> None:
        container = ttk.Frame(self.root, padding=16)
        container.pack(fill="both", expand=True)

        # ── Target & Port Input ───────────────────────────────────────
        form = ttk.Frame(container)
        form.pack(fill="x", pady=(0, 12))
        form.columnconfigure(1, weight=1)

        ttk.Label(form, text="Target").grid(row=0, column=0, sticky="w")
        self.target_var = tk.StringVar(value="127.0.0.1")
        ttk.Entry(form, textvariable=self.target_var, width=32).grid(row=1, column=0, padx=(0, 12), pady=(4, 12), sticky="w")

        ttk.Label(form, text="Ports").grid(row=0, column=1, sticky="w")
        self.ports_var = tk.StringVar(value="")
        ports_frame = ttk.Frame(form)
        ports_frame.grid(row=1, column=1, pady=(4, 12), sticky="we")
        ports_frame.columnconfigure(0, weight=1)
        ttk.Entry(ports_frame, textvariable=self.ports_var).grid(row=0, column=0, sticky="we")

        preset_button = tk.Menubutton(ports_frame, text="Presets", relief="raised")
        preset_menu = tk.Menu(preset_button, tearoff=False)
        preset_menu.add_command(label="Well-known ports", command=lambda: self._set_port_preset("wellknown"))
        preset_menu.add_command(label="All ports", command=lambda: self._set_port_preset("all"))
        preset_button.configure(menu=preset_menu)
        preset_button.grid(row=0, column=1, padx=(8, 0))

        # ── Scan Type Selection ──────────────────────────────────────
        scan_frame = ttk.LabelFrame(container, text="Scan Type", padding=8)
        scan_frame.pack(fill="x", pady=(0, 12))

        ttk.Radiobutton(scan_frame, text="TCP Connect", variable=self.scan_type_var, value="tcp_connect").pack(side="left", padx=5)
        ttk.Radiobutton(scan_frame, text="SYN Stealth", variable=self.scan_type_var, value="syn_stealth").pack(side="left", padx=5)
        ttk.Radiobutton(scan_frame, text="UDP", variable=self.scan_type_var, value="udp").pack(side="left", padx=5)
        ttk.Radiobutton(scan_frame, text="FIN", variable=self.scan_type_var, value="fin").pack(side="left", padx=5)
        ttk.Radiobutton(scan_frame, text="NULL", variable=self.scan_type_var, value="null").pack(side="left", padx=5)
        ttk.Radiobutton(scan_frame, text="XMAS", variable=self.scan_type_var, value="xmas").pack(side="left", padx=5)

        # ── Enhancement Options ──────────────────────────────────────
        enhance_frame = ttk.LabelFrame(container, text="Enhancements", padding=8)
        enhance_frame.pack(fill="x", pady=(0, 12))

        ttk.Checkbutton(enhance_frame, text="OS Detection", variable=self.os_detection_var).pack(side="left", padx=5)
        ttk.Checkbutton(enhance_frame, text="Service Detection", variable=self.service_detection_var).pack(side="left", padx=5)
        ttk.Checkbutton(enhance_frame, text="Vulnerability Scan", variable=self.vulnerability_scan_var).pack(side="left", padx=5)
        ttk.Checkbutton(enhance_frame, text="AI Enhancements", variable=self.ai_enhancements_var).pack(side="left", padx=5)

        # ── Action Buttons ───────────────────────────────────────────
        actions = ttk.Frame(container)
        actions.pack(fill="x", pady=(0, 12))

        self.scan_button = ttk.Button(actions, text="Start Scan", command=self.start_scan)
        self.scan_button.pack(side="left")

        self.stop_button = ttk.Button(actions, text="Stop Scan", command=self.stop_scan, state="disabled")
        self.stop_button.pack(side="left", padx=(8, 0))

        self.demo_button = ttk.Button(actions, text="Quick Demo", command=self.quick_localhost_demo)
        self.demo_button.pack(side="left", padx=(8, 0))

        self.traceroute_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(actions, text="Traceroute", variable=self.traceroute_var).pack(side="left", padx=(8, 0))

        self.export_button = ttk.Button(actions, text="Export PDF", command=self.export_pdf, state="disabled")
        self.export_button.pack(side="left", padx=(8, 0))

        self.status_var = tk.StringVar(value="Ready")
        ttk.Label(actions, textvariable=self.status_var).pack(side="right")

        # ── Progress Bar ─────────────────────────────────────────────
        self.progress_var = tk.DoubleVar(value=0)
        self.progress_bar = ttk.Progressbar(container, maximum=100, variable=self.progress_var)
        self.progress_bar.pack(fill="x", pady=(0, 12))

        # ── Summary ──────────────────────────────────────────────────
        self.summary_text = tk.Text(container, height=6, wrap="word")
        self.summary_text.pack(fill="x", pady=(0, 12))
        self.summary_text.insert("1.0", "No scan yet.")
        self.summary_text.configure(state="disabled")

        # ── Results Tabs ─────────────────────────────────────────────
        results_container = ttk.Frame(container)
        results_container.pack(fill="both", expand=True)

        self.results_notebook = ttk.Notebook(results_container)
        self.results_notebook.pack(fill="both", expand=True)

        open_tab = ttk.Frame(self.results_notebook)
        service_tab = ttk.Frame(self.results_notebook)
        vuln_tab = ttk.Frame(self.results_notebook)
        banner_tab = ttk.Frame(self.results_notebook)
        closed_tab = ttk.Frame(self.results_notebook)

        self.results_notebook.add(open_tab, text="Open Ports")
        self.results_notebook.add(service_tab, text="Services")
        self.results_notebook.add(vuln_tab, text="Vulnerabilities")
        self.results_notebook.add(banner_tab, text="Banners")
        self.results_notebook.add(closed_tab, text="Closed Ports")

        self.result_trees["open"] = self._build_result_tree(
            open_tab,
            (("port", "Port", 60), ("time", "Time (ms)", 100), ("service", "Service", 150), ("risk", "Risk", 60), ("banner", "Banner", 300)),
        )
        self.result_trees["service"] = self._build_result_tree(
            service_tab,
            (("port", "Port", 60), ("service", "Service", 120), ("version", "Version", 200), ("risk", "Risk", 80), ("cves", "CVEs", 60)),
        )
        self.result_trees["vuln"] = self._build_result_tree(
            vuln_tab,
            (("port", "Port", 60), ("service", "Service", 120), ("cvelist", "CVE IDs", 300), ("risk", "Risk", 80)),
        )
        self.result_trees["banner"] = self._build_result_tree(
            banner_tab,
            (("port", "Port", 80), ("time", "Time (ms)", 100), ("banner", "Banner", 500)),
        )
        self.result_trees["closed"] = self._build_result_tree(
            closed_tab,
            (("port", "Port", 80), ("time", "Time (ms)", 100), ("error", "Error", 500)),
        )

    def quick_localhost_demo(self) -> None:
        self.target_var.set("127.0.0.1")
        self.ports_var.set("22,80,443,3389")
        self.start_scan()

    def _set_port_preset(self, preset: str) -> None:
        self.ports_var.set(preset)

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
        self.stop_button.configure(state="normal")
        self.demo_button.configure(state="disabled")
        self.export_button.configure(state="disabled")
        self.scan_stop_event.clear()
        self.expected_results = len(ports)
        self.progress_var.set(0)
        self.progress_bar.configure(maximum=max(1, self.expected_results))
        self.status_var.set("Scanning...")
        self._clear_results()
        self.current_dns_resolution = resolve_target(target)
        self._update_summary_preview(target)

        self.scan_thread = threading.Thread(target=self._run_scan, args=(target, ports), daemon=True)
        self.scan_thread.start()

    def stop_scan(self) -> None:
        if self.scan_thread is None:
            return
        self.scan_stop_event.set()
        self.stop_button.configure(state="disabled")
        self.status_var.set("Stopping scan...")

    def _run_scan(self, target: str, ports: list[int]) -> None:
        self.scanner = PortScanner(
            scan_type=self.scan_type_var.get(),
            os_detection=self.os_detection_var.get(),
            service_detection=self.service_detection_var.get(),
            vulnerability_scan=self.vulnerability_scan_var.get(),
            ai_enhancements=self.ai_enhancements_var.get(),
        )
        session = self.scanner.scan(
            target,
            ports,
            progress_callback=self._on_progress,
            dns_resolution=self.current_dns_resolution,
            traceroute=self.traceroute_var.get(),
            stop_event=self.scan_stop_event,
        )
        self.latest_session = session
        self.root.after(0, lambda: self._show_session(session))

    def _on_progress(self, completed: int, total: int, result) -> None:
        self.root.after(0, lambda: self._update_progress(completed, total, result))

    def _update_progress(self, completed: int, total: int, result) -> None:
        self.progress_var.set(completed)
        state = "Open" if result.is_open else "Closed"
        self.status_var.set(f"Scanning... {completed}/{total} complete, last: port {result.port} {state}")

    def _show_session(self, session) -> None:
        self._update_summary(session)
        self._populate_results(session)
        if session.stopped:
            status_text = "Stopped"
        else:
            status_text = "Done"
        sections = build_result_sections(session)
        self.status_var.set(
            f"{status_text} - {len(session.open_ports)} open, {len(sections.service_ports)} services, {len(sections.vuln_ports)} vulns"
        )
        self.scan_button.configure(state="normal")
        self.stop_button.configure(state="disabled")
        self.demo_button.configure(state="normal")
        self.export_button.configure(state="normal")
        self.scan_thread = None
        self.progress_var.set(self.expected_results)

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
        for tree in self.result_trees.values():
            for item in tree.get_children():
                tree.delete(item)

    def _build_result_tree(
        self,
        parent: ttk.Frame,
        columns: tuple[tuple[str, str, int], ...],
    ) -> ttk.Treeview:
        frame = ttk.Frame(parent)
        frame.pack(fill="both", expand=True)

        tree_columns = tuple(column[0] for column in columns)
        tree = ttk.Treeview(frame, columns=tree_columns, show="headings")
        for column_name, heading, width in columns:
            tree.heading(column_name, text=heading)
            tree.column(column_name, width=width, anchor="center" if column_name in {"port", "time"} else "w")

        scrollbar = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=scrollbar.set)
        tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        return tree

    def _populate_results(self, session) -> None:
        sections = build_result_sections(session)
        self._clear_results()

        # Open ports tab
        for result in sections.open_ports:
            self.result_trees["open"].insert(
                "",
                "end",
                values=(
                    result.port,
                    f"{result.response_time_ms:.2f}" if result.response_time_ms else "-",
                    result.service_name or "-",
                    f"{result.risk_score}" if result.risk_score else "-",
                    result.banner or "-",
                ),
            )

        # Services tab
        for result in sections.service_ports:
            self.result_trees["service"].insert(
                "",
                "end",
                values=(
                    result.port,
                    result.service_name or "-",
                    result.service_version or "-",
                    f"{result.risk_score}" if result.risk_score else "-",
                    len(result.vulnerability_ids) if result.vulnerability_ids else 0,
                ),
            )

        # Vulnerabilities tab
        for result in sections.vuln_ports:
            cves = ", ".join(result.vulnerability_ids) if result.vulnerability_ids else "-"
            self.result_trees["vuln"].insert(
                "",
                "end",
                values=(
                    result.port,
                    result.service_name or "-",
                    cves,
                    f"{result.risk_score}" if result.risk_score else "-",
                ),
            )

        # Banners tab
        for result in sections.banner_ports:
            self.result_trees["banner"].insert(
                "",
                "end",
                values=(
                    result.port,
                    f"{result.response_time_ms:.2f}" if result.response_time_ms else "-",
                    result.banner or "-",
                ),
            )

        # Closed ports tab
        for result in sections.closed_ports:
            self.result_trees["closed"].insert(
                "",
                "end",
                values=(
                    result.port,
                    f"{result.response_time_ms:.2f}" if result.response_time_ms else "-",
                    result.error or "-",
                ),
            )

    def _update_summary(self, session) -> None:
        text = build_summary_text(session)
        self.summary_text.configure(state="normal")
        self.summary_text.delete("1.0", tk.END)
        self.summary_text.insert("1.0", text)
        self.summary_text.configure(state="disabled")

    def _update_summary_preview(self, target: str) -> None:
        dns = self.current_dns_resolution
        lines = [f"Target: {target}", "Ports scanned: pending..."]
        if dns is not None:
            if dns.error:
                lines.append(f"DNS lookup: failed ({dns.error})")
            else:
                lines.append(f"DNS lookup: {', '.join(dns.resolved_ips) if dns.resolved_ips else '-'}")
            if dns.lookup_time_ms is not None:
                lines.append(f"DNS time: {dns.lookup_time_ms:.2f} ms")
        if self.traceroute_var.get():
            lines.append("Traceroute: pending...")
        self.summary_text.configure(state="normal")
        self.summary_text.delete("1.0", tk.END)
        self.summary_text.insert("1.0", "\n".join(lines))
        self.summary_text.configure(state="disabled")
