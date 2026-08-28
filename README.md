# Port Scanner

Python-based port scanner with a minimal Tkinter UI and PDF report generation.
The scanner performs explicit DNS resolution before the port scan and shows the resolved IPs and lookup time in the UI and PDF report.
Port input accepts presets like `all`, `wellknown`, `common`, `fundamental`, and custom ranges like `1-1024` or `20,21,22`.
The scanner runs ports in 10-port parallel batches so larger scans stay controlled instead of firing thousands of sockets at once.

Project documentation:
- [Project report](docs/project_report.md)
- [Software requirements specification](docs/srs.md)

## Structure
- `src/scanner/` scan engine and target parsing
- `src/ui/` Tkinter interface
- `src/reporting/` PDF export
- `src/models/` scan data structures
- `src/utils/` formatting helpers

## Run
```bash
python main.py
```

Terminal modes:
```bash
python main.py google.com -p 1-100 --terminal
python main.py 127.0.0.1 -p wellknown --traceroute --tui
python main.py target google.com --port 80,443 --terminal
```

- `--terminal` prints grouped results after the scan.
- `--tui` shows a live terminal UI while scanning.
- `target HOST` is an optional nmap-style command form.
- `--port` and `--ports` are equivalent.
- `-p all`, `-p wellknown`, `-p fundamental`, and ranges like `1-1024` are supported.

## Local Demo
For a guaranteed open port during testing, run the temporary FastAPI smoke service in one terminal:
```bash
python -m uvicorn fastapi_test_service:app --host 127.0.0.1 --port 8001
```

Then open the scanner and use `127.0.0.1` with port `8001`, or click `Quick Localhost Demo`.

Examples:
- `all` scans all 65535 TCP ports.
- `wellknown` or `fundamental` scans the built-in common set.
- `1-1024` scans only the fundamental TCP range.
