from __future__ import annotations

import tkinter as tk

from src.ui.app import PortScannerApp


def main() -> None:
    root = tk.Tk()
    PortScannerApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
