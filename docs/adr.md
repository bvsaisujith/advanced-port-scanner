# ADR 0001: Python, Tkinter, and Modular Async Scanner Design

## Status
Accepted

## Context
The project must be completed quickly, use as few implementation credits as possible, and still present as a real multi-file application. The deliverable needs a minimal desktop frontend and PDF report generation.

## Decision
Use Python for the implementation, with a modular architecture split across multiple files. Build the scanning core first, then layer on a minimal Tkinter UI, then add PDF report generation.

## Rationale
- Python is faster to prototype than Go under a short deadline.
- The existing dependencies already suggest Python support for async networking, a Tkinter UI, and PDF export.
- A modular layout reduces the risk of a single large script becoming hard to debug.
- Tkinter is sufficient for a submission-grade desktop UI without extra UI framework complexity.
- PDF reporting can be added with a small dedicated module after scan data is stable.

## Consequences
### Positive
- Faster initial delivery
- Easier debugging and iteration
- Clear separation between engine, UI, and reporting layers
- Lower implementation risk for a 2-hour target

### Negative
- Python will not match Go for raw scan throughput at scale
- The first version will need conservative concurrency settings to avoid instability
- The UI will remain minimal rather than polished

## Alternatives Considered
### Go
Rejected for this submission because it would take longer to build and wire the UI and report output.

### Single-file Python script
Rejected because it would be harder to maintain, explain, and extend.

## Implementation Guidance
- Keep the scanner engine independent from Tkinter.
- Use small data models for scan results.
- Use bounded concurrency and timeouts.
- Generate the PDF from structured scan data, not directly from UI text.
- Keep all presentation formatting in the UI layer or report module.
