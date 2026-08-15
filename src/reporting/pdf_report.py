from __future__ import annotations

from pathlib import Path

from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

from src.models.scan_result import ScanSession


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

        y_position -= 10
        pdf.setFont("Helvetica-Bold", 10)
        pdf.drawString(40, y_position, "Port")
        pdf.drawString(90, y_position, "Status")
        pdf.drawString(150, y_position, "Response")
        pdf.drawString(230, y_position, "Banner")
        pdf.drawString(410, y_position, "Error")
        y_position -= 12

        pdf.setFont("Helvetica", 9)
        if not session.results:
            pdf.drawString(40, y_position, "No scan data available.")
        else:
            for result in session.results:
                if y_position < 50:
                    pdf.showPage()
                    pdf.setFont("Helvetica", 9)
                    y_position = height - 50

                status = "Open" if result.is_open else "Closed"
                response = f"{result.response_time_ms:.2f} ms" if result.response_time_ms is not None else "-"
                banner = (result.banner or "-")[:28]
                error = (result.error or "-")[:28]

                pdf.drawString(40, y_position, str(result.port))
                pdf.drawString(90, y_position, status)
                pdf.drawString(150, y_position, response)
                pdf.drawString(230, y_position, banner)
                pdf.drawString(410, y_position, error)
                y_position -= 14

        pdf.save()
