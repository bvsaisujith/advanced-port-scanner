from __future__ import annotations

import argparse
import tkinter as tk

from src.ui.app import PortScannerApp
from src.terminal.app import TerminalOptions, TerminalScannerApp


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Port Scanner")
    parser.add_argument("target", nargs="?", help="Target host or IP address")
    parser.add_argument("-p", "--ports", default="", help="Ports, presets, or ranges like 1-100 or all")
    parser.add_argument("--terminal", action="store_true", help="Run in terminal mode")
    parser.add_argument("--tui", action="store_true", help="Run with a live terminal UI")
    parser.add_argument("--traceroute", action="store_true", help="Run traceroute before scanning")
    parser.add_argument("--timeout", type=float, default=0.8, help="Per-port timeout in seconds")
    parser.add_argument("--workers", type=int, default=10, help="Maximum parallel workers")
    parser.add_argument("--batch-size", type=int, default=10, help="Ports per batch")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if args.terminal or args.tui or args.target:
        target = args.target or "127.0.0.1"
        options = TerminalOptions(
            target=target,
            ports=args.ports,
            traceroute=args.traceroute,
            tui=args.tui,
            timeout=args.timeout,
            max_workers=args.workers,
            batch_size=args.batch_size,
        )
        raise SystemExit(TerminalScannerApp().run(options))

    root = tk.Tk()
    PortScannerApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
