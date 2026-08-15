# Software Requirements Specification

## 1. Introduction
This document specifies the requirements for a Python-based port scanner application with a minimal Tkinter front end and PDF report generation.

## 2. Purpose
The purpose of the system is to scan TCP ports on a target host or range, present the findings in a small desktop interface, and generate a PDF report for submission or review.

## 3. Product Overview
The product is a local desktop application written in Python. It will use asynchronous or threaded concurrency for scanning, a Tkinter-based GUI for interaction, and a PDF library for report generation.

## 4. User Classes
- Primary user: student or reviewer running a lab-safe scan demo
- Secondary user: instructor or evaluator reading the report

## 5. Assumptions and Dependencies
- The environment is Windows
- Python 3.x is available
- The required packages in `requirements.txt` are installed
- Network targets are authorized for scanning
- PDF generation can be handled by a library such as WeasyPrint

## 6. System Features
### 6.1 Target Entry
The system shall allow entry of a hostname, IP address, or network range.

### 6.2 Port Selection
The system shall allow scanning either a comma-separated port list or a default common-port set.

### 6.3 Concurrent Scan Execution
The system shall scan ports using a bounded worker model so that many ports can be tested without blocking the UI.

### 6.4 Result Display
The system shall display scan results with at least the port number, state, and optional banner text.

### 6.5 Report Generation
The system shall generate a PDF report containing scan metadata, target information, open ports, closed ports summary, and timestamp.

### 6.6 Scan History in Memory
The system shall keep the current scan results in memory for reuse by the UI and report generator.

## 7. External Interface Requirements
### 7.1 User Interface
- Tkinter window
- Target input field
- Port input field
- Scan button
- Progress or status label
- Results table or text area
- Export PDF button

### 7.2 Software Interfaces
- Python standard library networking and threading/asyncio support
- PDF generation library
- Optional HTML-to-PDF rendering path if WeasyPrint is used

## 8. Non-Functional Requirements
### 8.1 Performance
The scanner should complete a small demo scan quickly enough for classroom use.

### 8.2 Reliability
The app should handle invalid input and common connection errors gracefully.

### 8.3 Maintainability
The code shall be split into multiple modules with clear responsibility boundaries.

### 8.4 Portability
The app should run on Windows without requiring advanced native setup beyond its documented dependencies.

## 9. Data Requirements
A scan result record should include:
- Target
- Port
- Status
- Response time or timeout
- Banner or service text when available
- Scan timestamp

## 10. Acceptance Criteria
- A user can run a scan from the UI without crashes.
- The app can scan multiple ports concurrently.
- The UI shows the results after the scan finishes.
- A PDF report can be generated from the latest scan.
- The project is organized into more than one source file.

## 11. Recommended Module Boundaries
- `src/models/scan_result.py`: data structures
- `src/scanner/port_scanner.py`: scan engine
- `src/scanner/target_parser.py`: target and port parsing
- `src/reporting/pdf_report.py`: PDF generation
- `src/ui/app.py`: Tkinter GUI
- `src/utils/formatters.py`: display helpers
- `main.py`: application entry point
