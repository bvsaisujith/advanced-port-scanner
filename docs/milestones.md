# Milestones

## Build Order
Follow this sequence so each layer has a stable foundation before the next one is added.

### Milestone 1: Project Skeleton
Goal: create the package structure and shared data model.
- Create `src/` package folders
- Add `main.py`
- Add result models and constants
- Add target and port parsing helpers
- Define the scan result shape used across the app

Exit criteria:
- Imports resolve cleanly
- The codebase is clearly multi-file
- Basic data structures exist before scan logic is added

### Milestone 2: Single-Port Scanner
Goal: prove the network scan works before adding concurrency.
- Implement one TCP connect check
- Add timeouts and error handling
- Return a normalized scan result object
- Test against localhost or an approved lab target

Exit criteria:
- One port can be scanned reliably from code
- Success, refusal, and timeout are handled cleanly

### Milestone 3: Concurrent Scanner Engine
Goal: scan many ports efficiently with bounded parallelism.
- Add worker pool or asyncio task scheduling
- Support batching of ports
- Keep concurrency limited to avoid resource spikes
- Aggregate results into a single scan session object

Exit criteria:
- Multiple ports scan in one run
- Runtime is acceptable for demo-sized targets
- UI remains isolated from engine logic

### Milestone 4: Minimal Tkinter Frontend
Goal: provide a simple working desktop UI.
- Build target and port input fields
- Add scan and export buttons
- Show status/progress updates
- Render scan results in a table or text area

Exit criteria:
- A user can run a scan from the GUI
- The app does not freeze during scanning
- The UI is intentionally minimal and easy to demonstrate

### Milestone 5: PDF Report Generation
Goal: export the scan results to a report file.
- Create a report data formatter
- Build a PDF template or HTML report source
- Include target, timestamp, summary, and results
- Save the file to a predictable output path

Exit criteria:
- A PDF is generated from the latest scan
- The report is readable and includes key results

### Milestone 6: Cleanup and Submission Polish
Goal: make the project presentable for grading.
- Add a short README if needed
- Check error messages and empty states
- Verify the folder structure is easy to explain
- Remove any prototype-only code

Exit criteria:
- The project can be demonstrated end to end
- The architecture is easy to describe during submission

## Suggested File Flow
1. `src/models/` and `src/utils/`
2. `src/scanner/`
3. `src/reporting/`
4. `src/ui/`
5. `main.py`

## What To Build First
Start with the scanner core, not the UI. The UI depends on stable scan results, and the PDF depends on the same data model. Build in this order:
1. Data model
2. Input parsing
3. Single-port scan
4. Concurrent scanning
5. Tkinter UI
6. PDF generation
7. Final cleanup
