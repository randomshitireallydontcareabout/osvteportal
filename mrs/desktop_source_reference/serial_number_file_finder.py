#!/usr/bin/env python3
"""Serial Number File Finder plug-in for the OSV Master GUI."""

import csv
import os
import queue
import re
import threading
import tkinter as tk
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

APP_TITLE = "Serial Number File Finder"
SUPPORTED_EXTENSIONS = {".log", ".html", ".htm", ".err", ".txt", ".xml"}

BG = "#07111D"
PANEL = "#0A1A2A"
CARD = "#0D2235"
LINE = "#173A55"
BLUE = "#0D7CC1"
CYAN = "#22B8EE"
TEXT = "#F3F7FB"
MUTED = "#9BB3C7"
SUCCESS = "#3DD6A1"
DANGER = "#FF6B6B"


def normalized_serial(value):
    """Normalize for matching while preserving letters and digits."""
    return re.sub(r"[^A-Za-z0-9]", "", value or "").upper()


def readable_text(path):
    """Read common log/text formats using safe encoding fallbacks."""
    data = path.read_bytes()
    if b"\x00" in data[:4096]:
        for encoding in ("utf-16", "utf-16-le", "utf-16-be"):
            try:
                return data.decode(encoding)
            except UnicodeError:
                pass
    for encoding in ("utf-8-sig", "utf-8", "cp1252", "latin-1"):
        try:
            return data.decode(encoding)
        except UnicodeError:
            pass
    return data.decode("utf-8", errors="replace")


class GradientHeader(tk.Canvas):
    """Responsive dark-blue to cyan gradient used by the OSV Master GUI theme."""

    def __init__(self, parent, start="#0A1725", end="#07517A", **kwargs):
        kwargs.setdefault("highlightthickness", 0)
        kwargs.setdefault("borderwidth", 0)
        kwargs.setdefault("bg", start)
        super().__init__(parent, **kwargs)
        self.start_color = start
        self.end_color = end
        self.bind("<Configure>", self._draw, add="+")

    def _rgb(self, color):
        red, green, blue = self.winfo_rgb(color)
        return red // 256, green // 256, blue // 256

    def _draw(self, _event=None):
        self.delete("gradient")
        width = max(self.winfo_width(), 1)
        height = max(self.winfo_height(), 1)
        start = self._rgb(self.start_color)
        end = self._rgb(self.end_color)
        for x in range(width):
            ratio = x / max(width - 1, 1)
            color = "#{:02x}{:02x}{:02x}".format(*(
                int(start[index] + (end[index] - start[index]) * ratio)
                for index in range(3)
            ))
            self.create_line(x, 0, x, height, fill=color, tags="gradient")
        self.tag_lower("gradient")


class SerialFinderApp(tk.Frame):
    def __init__(self, parent, master_root=None):
        self.master_root = master_root or parent.winfo_toplevel()
        super().__init__(parent, bg=BG)
        self.pack(fill="both", expand=True)

        self.serial_var = tk.StringVar()
        self.directory_var = tk.StringVar()
        self.status_var = tk.StringVar(value="Enter a serial number, then select a directory.")
        self.recursive_var = tk.BooleanVar(value=True)
        self.results = []
        self.worker = None
        self.cancel_event = threading.Event()
        self.events = queue.Queue()

        self._configure_style()
        self._build_ui()
        self.after(100, self._process_events)

    def _configure_style(self):
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("Finder.TFrame", background=BG)
        style.configure("FinderCard.TFrame", background=CARD, relief="flat")
        style.configure("Finder.TLabel", background=BG, foreground=TEXT)
        style.configure("FinderMuted.TLabel", background=BG, foreground=MUTED)
        style.configure("FinderCard.TLabel", background=CARD, foreground=TEXT)
        style.configure("FinderCardMuted.TLabel", background=CARD, foreground=MUTED)
        style.configure("Finder.TCheckbutton", background=CARD, foreground=TEXT, focuscolor=CARD)
        style.configure("FinderPrimary.TButton", background=BLUE, foreground="white", padding=(14, 9), font=("Segoe UI", 10, "bold"))
        style.map("FinderPrimary.TButton", background=[("active", CYAN), ("disabled", "#31506A")])
        style.configure("FinderSecondary.TButton", background="#173A55", foreground=TEXT, padding=(12, 8))
        style.map("FinderSecondary.TButton", background=[("active", "#245878")])
        style.configure("Finder.Treeview", background="#091725", fieldbackground="#091725", foreground=TEXT, rowheight=31, borderwidth=0, font=("Segoe UI", 10))
        style.configure("Finder.Treeview.Heading", background="#12304A", foreground=TEXT, relief="flat", font=("Segoe UI", 10, "bold"))
        style.map("Finder.Treeview", background=[("selected", BLUE)], foreground=[("selected", "white")])

    def _build_ui(self):
        header = GradientHeader(self, height=92)
        header.pack(fill="x", padx=18, pady=(18, 12))
        header.pack_propagate(False)
        title_box = tk.Frame(header, bg="#0A1A2A")
        title_box.pack(side="left", fill="both", expand=True, padx=5, pady=5)
        tk.Frame(title_box, bg=CYAN, width=5).pack(side="left", fill="y")
        title_copy = tk.Frame(title_box, bg="#0A1A2A")
        title_copy.pack(side="left", fill="both", expand=True, padx=20, pady=12)
        tk.Label(title_copy, text=APP_TITLE, bg="#0A1A2A", fg=TEXT, font=("Segoe UI", 24, "bold")).pack(anchor="w")
        tk.Label(title_copy, text="Find each matching file once using the full serial number or its last five characters.", bg="#0A1A2A", fg=MUTED, font=("Segoe UI", 10)).pack(anchor="w", pady=(4, 0))

        search_card = ttk.Frame(self, style="FinderCard.TFrame", padding=18)
        search_card.pack(fill="x", padx=18, pady=(0, 10))
        search_card.columnconfigure(1, weight=1)

        ttk.Label(search_card, text="1  SERIAL NUMBER", style="FinderCard.TLabel", font=("Segoe UI", 10, "bold")).grid(row=0, column=0, sticky="w", padx=(0, 14))
        serial_entry = ttk.Entry(search_card, textvariable=self.serial_var, font=("Segoe UI", 11))
        serial_entry.grid(row=0, column=1, sticky="ew", ipady=5)
        serial_entry.bind("<Return>", lambda _event: self.start_search())

        ttk.Label(search_card, text="2  DIRECTORY", style="FinderCard.TLabel", font=("Segoe UI", 10, "bold")).grid(row=1, column=0, sticky="w", padx=(0, 14), pady=(14, 0))
        ttk.Entry(search_card, textvariable=self.directory_var, font=("Segoe UI", 10)).grid(row=1, column=1, sticky="ew", ipady=5, pady=(14, 0))
        ttk.Button(search_card, text="BROWSE", style="FinderSecondary.TButton", command=self.browse_directory).grid(row=1, column=2, padx=(10, 0), pady=(14, 0))

        options = ttk.Frame(search_card, style="FinderCard.TFrame")
        options.grid(row=2, column=0, columnspan=3, sticky="ew", pady=(15, 0))
        ttk.Checkbutton(options, text="Include subfolders", variable=self.recursive_var, style="Finder.TCheckbutton").pack(side="left")
        ttk.Label(options, text="Supported files  •  LOG  •  HTML  •  ERR  •  TXT  •  XML", style="FinderCardMuted.TLabel").pack(side="left", padx=18)
        self.search_button = ttk.Button(options, text="SEARCH FILES", style="FinderPrimary.TButton", command=self.start_search)
        self.search_button.pack(side="right")
        self.cancel_button = ttk.Button(options, text="CANCEL", style="FinderSecondary.TButton", command=self.cancel_search, state="disabled")
        self.cancel_button.pack(side="right", padx=(0, 8))

        status_row = ttk.Frame(self, style="Finder.TFrame")
        status_row.pack(fill="x", padx=22, pady=(2, 7))
        self.progress = ttk.Progressbar(status_row, mode="indeterminate", length=170)
        self.progress.pack(side="right")
        ttk.Label(status_row, textvariable=self.status_var, style="FinderMuted.TLabel").pack(side="left")

        result_card = ttk.Frame(self, style="FinderCard.TFrame", padding=12)
        result_card.pack(fill="both", expand=True, padx=18, pady=(0, 18))
        result_card.rowconfigure(0, weight=1)
        result_card.columnconfigure(0, weight=1)

        columns = ("match", "file", "occurrences", "line", "modified", "path")
        self.tree = ttk.Treeview(result_card, columns=columns, show="headings", style="Finder.Treeview", selectmode="browse")
        headings = {"match": "Best Match", "file": "File", "occurrences": "Matches", "line": "First Line", "modified": "Modified", "path": "Full Path"}
        widths = {"match": 110, "file": 210, "occurrences": 70, "line": 75, "modified": 140, "path": 500}
        for column in columns:
            self.tree.heading(column, text=headings[column])
            self.tree.column(column, width=widths[column], anchor="w", stretch=column in {"file", "path"})
        self.tree.grid(row=0, column=0, sticky="nsew")
        self.tree.bind("<Double-1>", self.open_selected_file)
        y_scroll = ttk.Scrollbar(result_card, orient="vertical", command=self.tree.yview)
        y_scroll.grid(row=0, column=1, sticky="ns")
        x_scroll = ttk.Scrollbar(result_card, orient="horizontal", command=self.tree.xview)
        x_scroll.grid(row=1, column=0, sticky="ew")
        self.tree.configure(yscrollcommand=y_scroll.set, xscrollcommand=x_scroll.set)

        bottom = ttk.Frame(result_card, style="FinderCard.TFrame")
        bottom.grid(row=2, column=0, columnspan=2, sticky="ew", pady=(10, 0))
        ttk.Button(bottom, text="OPEN SELECTED FILE", style="FinderSecondary.TButton", command=self.open_selected_file).pack(side="left")
        ttk.Button(bottom, text="OPEN FILE LOCATION", style="FinderSecondary.TButton", command=self.open_selected_location).pack(side="left", padx=8)
        ttk.Button(bottom, text="EXPORT RESULTS", style="FinderSecondary.TButton", command=self.export_results).pack(side="right")
        serial_entry.focus_set()

    def browse_directory(self):
        selected = filedialog.askdirectory(parent=self.master_root, title="Select the directory to search")
        if selected:
            self.directory_var.set(selected)

    def start_search(self):
        if self.worker and self.worker.is_alive():
            return
        serial = normalized_serial(self.serial_var.get())
        directory = Path(self.directory_var.get().strip())
        if len(serial) < 5:
            messagebox.showwarning("Serial Number", "Enter at least five letters or digits for the serial number.", parent=self.master_root)
            return
        if not directory.is_dir():
            messagebox.showwarning("Directory", "Select a valid directory to search.", parent=self.master_root)
            return

        self.results.clear()
        self.tree.delete(*self.tree.get_children())
        self.cancel_event.clear()
        self.search_button.configure(state="disabled")
        self.cancel_button.configure(state="normal")
        self.progress.start(12)
        self.status_var.set("Scanning supported files...")
        self.worker = threading.Thread(target=self._search_worker, args=(serial, directory, self.recursive_var.get()), daemon=True)
        self.worker.start()

    def cancel_search(self):
        self.cancel_event.set()
        self.status_var.set("Canceling search...")

    def _search_worker(self, serial, directory, recursive):
        try:
            iterator = directory.rglob("*") if recursive else directory.glob("*")
            files = [path for path in iterator if path.is_file() and path.suffix.lower() in SUPPORTED_EXTENSIONS]
            full_token = serial
            short_token = serial[-5:]
            matched_files = 0
            matched_occurrences = 0

            for index, path in enumerate(files, 1):
                if self.cancel_event.is_set():
                    self.events.put(("done", True, len(files), matched_files, matched_occurrences))
                    return
                self.events.put(("status", f"Reading {index} of {len(files)}: {path.name}"))
                try:
                    text = readable_text(path)
                except OSError as exc:
                    self.events.put(("error", str(path), str(exc)))
                    continue

                # Consolidate all occurrences into ONE result per file. Full-serial
                # matches take priority over last-five matches for the displayed type.
                full_matches = []
                short_matches = []
                for line_number, line in enumerate(text.splitlines(), 1):
                    compact_line = normalized_serial(line)
                    snippet = re.sub(r"\s+", " ", line).strip()[:240]
                    if full_token in compact_line:
                        full_matches.append((line_number, snippet))
                    elif short_token in compact_line:
                        short_matches.append((line_number, snippet))

                all_matches = full_matches + short_matches
                if not all_matches:
                    continue

                matched_files += 1
                matched_occurrences += len(all_matches)
                best_matches = full_matches if full_matches else short_matches
                match_type = "Full serial" if full_matches else "Last 5"
                first_line, first_snippet = min(best_matches, key=lambda item: item[0])
                try:
                    modified = datetime.fromtimestamp(path.stat().st_mtime).strftime("%Y-%m-%d %H:%M")
                except OSError:
                    modified = "Unknown"

                result = {
                    "match": match_type,
                    "file": path.name,
                    "occurrences": len(all_matches),
                    "line": first_line,
                    "modified": modified,
                    "path": str(path),
                    "snippet": first_snippet,
                }
                self.results.append(result)
                self.events.put(("result", result))

            self.events.put(("done", False, len(files), matched_files, matched_occurrences))
        except Exception as exc:
            self.events.put(("fatal", str(exc)))

    def _process_events(self):
        try:
            while True:
                event = self.events.get_nowait()
                kind = event[0]
                if kind == "status":
                    self.status_var.set(event[1])
                elif kind == "result":
                    result = event[1]
                    item_id = self.tree.insert("", "end", values=(result["match"], result["file"], result["occurrences"], result["line"], result["modified"], result["path"]))
                    self.tree.see(item_id)
                elif kind == "error":
                    pass
                elif kind == "fatal":
                    self._finish_ui()
                    messagebox.showerror("Search Error", event[1], parent=self.master_root)
                elif kind == "done":
                    canceled, scanned, matched_files, occurrences = event[1:]
                    self._finish_ui()
                    if canceled:
                        self.status_var.set(f"Search canceled. Scanned up to {scanned} supported files; {occurrences} match(es) retained.")
                    else:
                        self.status_var.set(f"Complete: {scanned} supported files scanned, {matched_files} file(s) matched, {occurrences} occurrence(s) found.")
        except queue.Empty:
            pass
        if self.winfo_exists():
            self.after(100, self._process_events)

    def _finish_ui(self):
        self.progress.stop()
        self.search_button.configure(state="normal")
        self.cancel_button.configure(state="disabled")

    def selected_result(self):
        selection = self.tree.selection()
        if not selection:
            messagebox.showinfo("Select Result", "Select a result first.", parent=self.master_root)
            return None
        index = self.tree.index(selection[0])
        return self.results[index] if 0 <= index < len(self.results) else None

    def open_selected_file(self, event=None):
        result = self.selected_result()
        if not result:
            return
        try:
            os.startfile(result["path"])
        except AttributeError:
            import subprocess
            subprocess.Popen(["xdg-open", result["path"]])
        except OSError as exc:
            messagebox.showerror("Open File", str(exc), parent=self.master_root)

    def open_selected_location(self):
        result = self.selected_result()
        if not result:
            return
        path = Path(result["path"])
        try:
            if os.name == "nt":
                os.startfile(str(path.parent))
            else:
                import subprocess
                subprocess.Popen(["xdg-open", str(path.parent)])
        except OSError as exc:
            messagebox.showerror("Open Location", str(exc), parent=self.master_root)

    def export_results(self):
        if not self.results:
            messagebox.showinfo("Export Results", "There are no results to export.", parent=self.master_root)
            return
        target = filedialog.asksaveasfilename(parent=self.master_root, title="Export search results", defaultextension=".csv", filetypes=[("CSV files", "*.csv")], initialfile="serial-search-results.csv")
        if not target:
            return
        with open(target, "w", newline="", encoding="utf-8-sig") as handle:
            writer = csv.DictWriter(handle, fieldnames=("match", "file", "occurrences", "line", "modified", "path", "snippet"))
            writer.writeheader()
            writer.writerows(self.results)
        messagebox.showinfo("Export Results", f"Results saved to:\n{target}", parent=self.master_root)

    def cleanup(self):
        self.cancel_event.set()


def create_embedded_app(parent, master_root=None):
    """Required entrypoint used by master_launcher.py."""
    return SerialFinderApp(parent, master_root=master_root)


def run_standalone():
    root = tk.Tk()
    root.title(APP_TITLE)
    root.geometry("1250x780")
    root.minsize(900, 600)
    SerialFinderApp(root, master_root=root)
    root.mainloop()


if __name__ == "__main__":
    run_standalone()
