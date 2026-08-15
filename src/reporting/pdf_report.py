from __future__ import annotations

from pathlib import Path

from reportlab.lib.utils import simpleSplit
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

from src.models.scan_result import ScanSession
from src.utils.formatters import build_result_sections


class PdfReportGenerator:
    def generate(self, session: ScanSession, output_path: str | Path) -> Path:
        destination = Path(output_path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        self._write_pdf(session, destination)
        return destination

    def _write_pdf(self, session: ScanSession, destination: Path) -> None:
        pdf = canvas.Canvas(str(destination), pagesize=letter)
        width, height = letter
        y_position = height - 50
        started = session.started_at.strftime("%Y-%m-%d %H:%M:%S")
        finished = session.finished_at.strftime("%Y-%m-%d %H:%M:%S") if session.finished_at else "-"
        dns = session.dns_resolution
        sections = build_result_sections(session)

        pdf.setTitle("Port Scan Report")
        pdf.setFont("Helvetica-Bold", 18)
        pdf.drawString(40, y_position, "Port Scan Report")

        y_position -= 30
        pdf.setFont("Helvetica", 10)
        meta_lines = [
            f"Target: {session.target}",
            f"Ports scanned: {len(session.ports)}",
            f"Open ports: {len(session.open_ports)}",
            f"Started: {started}",
            f"Finished: {finished}",
        ]
        for line in meta_lines:
            pdf.drawString(40, y_position, line)
            y_position -= 14

        if dns is not None:
            dns_line = "DNS lookup: failed"
            if not dns.error:
                ipv4 = ", ".join(dns.ipv4_addresses) if dns.ipv4_addresses else "-"
                ipv6 = ", ".join(dns.ipv6_addresses) if dns.ipv6_addresses else "-"
                dns_line = f"DNS lookup: IPv4 [{ipv4}] | IPv6 [{ipv6}]"
            pdf.drawString(40, y_position, dns_line)
            y_position -= 14
            if dns.lookup_time_ms is not None:
                pdf.drawString(40, y_position, f"DNS time: {dns.lookup_time_ms:.2f} ms")
                y_position -= 14

        traceroute_lines = self._traceroute_lines(session)
        if traceroute_lines:
            y_position -= 4
            pdf.setFont("Helvetica-Bold", 10)
            pdf.drawString(40, y_position, "Traceroute")
            y_position -= 12
            pdf.setFont("Helvetica", 9)
            for line in traceroute_lines:
                for wrapped_line in simpleSplit(line, "Helvetica", 9, 520):
                    if y_position < 50:
                        pdf.showPage()
                        pdf.setFont("Helvetica", 9)
                        y_position = height - 50
                    pdf.drawString(40, y_position, wrapped_line)
                    y_position -= 11

        y_position -= 10
        y_position = self._write_section(pdf, y_position, height, "Open Ports", sections.open_ports, "banner")
        y_position = self._write_section(pdf, y_position, height, "Ports With Banners", sections.banner_ports, "banner")
        self._write_section(pdf, y_position, height, "Closed Ports", sections.closed_ports, "error")

        pdf.save()

    def _traceroute_lines(self, session: ScanSession) -> list[str]:
        if session.traceroute_error:
            return [f"Traceroute: failed ({session.traceroute_error})"]

        if not session.traceroute_output:
            return []

        lines = [line.strip() for line in session.traceroute_output.splitlines() if line.strip()]
        if session.traceroute_time_ms is not None:
            lines.insert(0, f"Traceroute time: {session.traceroute_time_ms:.2f} ms")
        lines.insert(0, "Traceroute: captured")
        return lines[:8]

    def _write_section(self, pdf: canvas.Canvas, y_position: int, height: int, title: str, results, terminal_field: str) -> int:
        pdf.setFont("Helvetica-Bold", 10)
        if y_position < 90:
            pdf.showPage()
            y_position = height - 50
        pdf.drawString(40, y_position, title)
        y_position -= 12

        pdf.setFont("Helvetica-Bold", 9)
        pdf.drawString(40, y_position, "Port")
        pdf.drawString(100, y_position, "Response")
        pdf.drawString(180, y_position, "Banner" if terminal_field == "banner" else "Error")
        y_position -= 11

        pdf.setFont("Helvetica", 9)
        if not results:
            pdf.drawString(40, y_position, "No data.")
            return y_position - 16

        for result in results:
            if y_position < 50:
                pdf.showPage()
                pdf.setFont("Helvetica", 9)
                y_position = height - 50

            response = f"{result.response_time_ms:.2f} ms" if result.response_time_ms is not None else "-"
            value = (result.banner if terminal_field == "banner" else result.error) or "-"
            pdf.drawString(40, y_position, str(result.port))
            pdf.drawString(100, y_position, response)
            pdf.drawString(180, y_position, value[:72])
            y_position -= 14

        return y_position - 6
