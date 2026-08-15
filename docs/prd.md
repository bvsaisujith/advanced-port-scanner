# Product Requirements Document

## Project
Python Port Scanner with minimal GUI and PDF reporting

## Goal
Build a lightweight, submission-ready port scanner that can scan target hosts, show results in a minimal Tkinter UI, and export a PDF report. The project should be modular, easy to explain, and small enough to finish within a short deadline.

## Target Outcome
A working desktop utility that:
- Accepts a target host or CIDR range
- Scans a user-selected list of ports or a default common-port list
- Runs scans concurrently to keep runtime short
- Displays results in a minimal Tkinter interface
- Generates a PDF report from the scan output

## Primary Users
- Student reviewer evaluating the submission
- Developer/demo user running scans in a lab or authorized environment

## Success Criteria
- The scanner works end to end from the UI
- Scan execution is fast enough for small and medium target sets
- Results are saved or exportable as a PDF report
- The codebase is split into multiple files, not a single script
- The implementation is simple enough to explain during review

## Scope
### In scope
- TCP connect scan using Python standard networking primitives or asyncio-based sockets
- Concurrent batch scanning
- Basic host validation and input sanitization
- Minimal Tkinter UI
- PDF report generation
- Scan history kept in memory for the current run
- Summary metrics such as total ports scanned, open ports found, elapsed time

### Out of scope for the first submission
- Raw packet crafting
- Full OS fingerprinting
- UDP scan support
- Service version detection
- NSE-style scripts or plugin system
- Authentication or remote agent features
- Distributed scanning

## User Story
As a user, I want to enter a target and ports, run a scan quickly, see the open ports, and export a PDF report so I can demonstrate a functional network tool in a short project submission.

## Functional Requirements
1. The app shall accept a single host or a network range.
2. The app shall accept either a port list or a predefined default list.
3. The app shall scan ports concurrently using bounded workers.
4. The app shall show open and closed results in the UI.
5. The app shall generate a PDF report after the scan completes.
6. The app shall keep the UI responsive while scanning.
7. The app shall store scan metadata for the report.

## Non-Functional Requirements
- Fast enough to run within a classroom submission demo
- Small dependency footprint
- Clear module boundaries
- Reasonable default timeout values
- Predictable behavior on Windows

## Constraints
- Deadline is short, so the first version must prioritize working software over advanced features.
- The UI must stay minimal to reduce implementation and testing cost.
- The report generator should be simple and reliable rather than highly styled.

## Proposed Architecture
- `src/scanner/` for core port scanning logic
- `src/ui/` for the Tkinter interface
- `src/reporting/` for PDF generation
- `src/models/` for scan result data structures
- `src/utils/` for parsing, validation, and formatting helpers
- `main.py` as the entry point

## Development Principles
- Build the scanner core before the UI.
- Add concurrency only after a single-port scan works.
- Add PDF generation only after results are reliably captured.
- Keep the first version boring and dependable.
- Prefer readable code over clever abstractions.
