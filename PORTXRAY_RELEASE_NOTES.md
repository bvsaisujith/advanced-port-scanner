# PortXray - Advanced Port Scanner
## Release Notes v1.0

### What is PortXray?
PortXray is a professional-grade port scanning and network analysis tool with an intuitive GUI. It combines advanced scanning techniques with modern security analysis features.

---

## Key Features

### 1. Multi-Scan Techniques
- **TCP Connect Scan** - Standard connection-based scanning
- **SYN Stealth Scan** - Stealth scanning with raw sockets
- **UDP Scan** - UDP port detection
- **FIN/NULL/XMAS Scans** - Advanced TCP flag-based scanning

### 2. OS Detection
- Passive OS fingerprinting (TTL analysis)
- Active ICMP-based detection
- Heuristic port-based OS guessing
- Confidence scoring (0-100%)

### 3. Service & Version Detection
- 50+ service signatures
- Banner grabbing and parsing
- Version extraction
- Service classification

### 4. Vulnerability Mapping
- CVE database integration
- Service-to-CVE mapping
- CVSS severity scoring
- Risk assessment per port

### 5. AI-Powered Enhancements
- Anomaly detection
- Risk scoring (0-10 scale)
- Behavioral pattern analysis
- Port density analysis

### 6. Professional Reporting
- PDF report generation
- Comprehensive scan summaries
- Service tables
- Vulnerability findings
- OS detection results

### 7. Modern Dashboard
- Tabbed interface with 6 result views:
  - Open Ports (with service & risk)
  - OS Detection (with confidence)
  - Services (discovered services)
  - Vulnerabilities (CVE findings)
  - Banners (raw data)
  - Closed Ports
- Real-time progress tracking
- Professional branding with logo

---

## Installation & Usage

### Option 1: Standalone Executable (Recommended)
Simply run `PortXray.exe` from the dist folder. No installation required!

```bash
D:\Supraja Technologies\Project\advanced-port-scanner\dist\PortXray.exe
```

### Option 2: From Source
```bash
cd "D:\Supraja Technologies\Project\advanced-port-scanner"
python -m pip install -r requirements.txt
python main.py
```

### Terminal Modes
```bash
# Basic terminal scan
python main.py google.com -p 1-100 --terminal

# Live TUI with traceroute
python main.py 127.0.0.1 -p wellknown --traceroute --tui

# Custom ports
python main.py target 192.168.1.1 --port 22,80,443 --terminal
```

---

## UI Improvements (v1.0)

### Premium Header Design
- **Logo Integration**: Professional PortXray logo display
- **Modern Typography**: Segoe UI fonts with 36pt bold title
- **Color Scheme**: Professional blue (#0052cc) with gray accents
- **Clean Layout**: Logo on left, title on right with divider

### Dashboard Enhancements
- Tabbed results view for organized data presentation
- OS Detection tab showing target OS and confidence
- Service detection with version information
- Vulnerability findings with CVE IDs
- Risk scoring displayed across all tabs

### Visual Polish
- White header with clean divider line
- Consistent color scheme throughout
- Professional appearance suitable for enterprise use
- Responsive layout

---

## System Requirements

### Minimum
- Windows 7 or later
- 2GB RAM
- 50MB disk space

### Recommended
- Windows 10/11
- 4GB+ RAM
- SSD storage for reports

### For Source Installation
- Python 3.8+
- See `requirements.txt` for dependencies

---

## File Structure

```
PortXray/
├── dist/
│   └── PortXray.exe          # Standalone executable
├── src/
│   ├── scanner/              # Core scanning engines
│   ├── ui/                   # GUI components
│   ├── reporting/            # PDF report generation
│   ├── models/               # Data structures
│   └── utils/                # Utilities
├── main.py                   # Entry point
├── requirements.txt          # Dependencies
└── README.md                 # Documentation
```

---

## Advanced Options

### Scan Configuration
- **Timeout**: Adjustable per-port timeout (default: 0.8s)
- **Workers**: Parallel scanning threads (default: 10)
- **Batch Size**: Ports per batch (default: 10)

### Feature Toggles
- OS Detection: Enable/disable OS fingerprinting
- Service Detection: Banner grabbing and identification
- Vulnerability Scan: CVE mapping
- AI Enhancements: Anomaly detection

---

## Limitations & Known Issues

1. **SYN/FIN/NULL/XMAS Scans**: Require administrator/root privileges on Windows
   - Falls back to TCP Connect automatically if unavailable
2. **CVE Database**: Local curated subset (can be extended)
3. **Traceroute**: Requires Windows tracert utility availability

---

## Future Enhancements

- [ ] Live CVE API integration (NVD)
- [ ] Matplotlib charts in PDF reports
- [ ] ML-based anomaly detection
- [ ] Distributed scanning support
- [ ] JSON/CSV export formats
- [ ] Web-based interface
- [ ] Real-time notification system

---

## Support & License

**License**: MIT (see LICENSE file)

For issues or feature requests, refer to the project documentation or contact Supraja Technologies.

---

## Version History

### v1.0 (Aug 30, 2026)
- ✅ Release: PortXray with professional branding
- ✅ Features: All 7 core features implemented
- ✅ UI: Modern dashboard with OS Detection display
- ✅ Executable: Standalone Windows EXE (23MB)

---

**Created by**: Supraja Technologies  
**Release Date**: August 30, 2026  
**Application**: PortXray Advanced Port Scanner v1.0
