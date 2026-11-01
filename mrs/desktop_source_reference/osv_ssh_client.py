#!/usr/bin/env python3
"""Authorized SSH client plug-in for the OSV Master GUI."""

import queue
import socket
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

try:
    import paramiko
except ImportError:
    paramiko = None

APP_TITLE = "OSV SSH Client"
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


class GradientHeader(tk.Canvas):
    """Responsive OSV dark-blue gradient header."""

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
            values = [int(start[i] + (end[i] - start[i]) * ratio) for i in range(3)]
            color = "#{:02x}{:02x}{:02x}".format(*values)
            self.create_line(x, 0, x, height, fill=color, tags="gradient")
        self.tag_lower("gradient")


class OSVSSHClient(tk.Frame):
    def __init__(self, parent, master_root=None):
        self.master_root = master_root or parent.winfo_toplevel()
        super().__init__(parent, bg=BG)
        self.pack(fill="both", expand=True)

        self.client = None
        self.connected = False
        self.connecting = False
        self.events = queue.Queue()
        self.worker = None

        self.host_var = tk.StringVar()
        self.port_var = tk.StringVar(value="22")
        self.username_var = tk.StringVar()
        self.password_var = tk.StringVar()
        self.auth_mode_var = tk.StringVar(value="Password")
        self.key_path_var = tk.StringVar()
        self.key_passphrase_var = tk.StringVar()
        self.timeout_var = tk.StringVar(value="10")
        self.command_var = tk.StringVar()
        self.status_var = tk.StringVar(value="Disconnected")
        self.verify_host_key_var = tk.BooleanVar(value=True)

        self._configure_style()
        self._build_ui()
        self._update_auth_fields()
        self.after(100, self._process_events)

    def _configure_style(self):
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("SSH.TFrame", background=BG)
        style.configure("SSHCard.TFrame", background=CARD)
        style.configure("SSH.TLabel", background=BG, foreground=TEXT)
        style.configure("SSHMuted.TLabel", background=BG, foreground=MUTED)
        style.configure("SSHCard.TLabel", background=CARD, foreground=TEXT)
        style.configure("SSHCardMuted.TLabel", background=CARD, foreground=MUTED)
        style.configure("SSH.TCheckbutton", background=CARD, foreground=TEXT, focuscolor=CARD)
        style.configure("SSHPrimary.TButton", background=BLUE, foreground="white", padding=(14, 9), font=("Segoe UI", 10, "bold"))
        style.map("SSHPrimary.TButton", background=[("active", CYAN), ("disabled", "#31506A")])
        style.configure("SSHSecondary.TButton", background="#173A55", foreground=TEXT, padding=(12, 8))
        style.map("SSHSecondary.TButton", background=[("active", "#245878")])
        style.configure("SSH.TCombobox", fieldbackground="#091725", background="#173A55", foreground=TEXT)

    def _build_ui(self):
        header = GradientHeader(self, height=88)
        header.pack(fill="x", padx=18, pady=(18, 12))
        header.pack_propagate(False)
        header_inner = tk.Frame(header, bg=PANEL)
        header_inner.pack(fill="both", expand=True, padx=5, pady=5)
        tk.Frame(header_inner, bg=CYAN, width=5).pack(side="left", fill="y")
        copy = tk.Frame(header_inner, bg=PANEL)
        copy.pack(side="left", fill="both", expand=True, padx=20, pady=11)
        tk.Label(copy, text=APP_TITLE, bg=PANEL, fg=TEXT, font=("Segoe UI", 24, "bold")).pack(anchor="w")
        tk.Label(copy, text="Connect to authorized systems using a password or private SSH key, then run commands.", bg=PANEL, fg=MUTED, font=("Segoe UI", 10)).pack(anchor="w", pady=(3, 0))

        connection = ttk.Frame(self, style="SSHCard.TFrame", padding=16)
        connection.pack(fill="x", padx=18, pady=(0, 10))
        for column in (1, 3):
            connection.columnconfigure(column, weight=1)

        self._field(connection, "HOST / IP", self.host_var, 0, 0)
        self._field(connection, "PORT", self.port_var, 0, 2, width=8)
        self._field(connection, "USERNAME", self.username_var, 1, 0)

        ttk.Label(connection, text="AUTHENTICATION", style="SSHCard.TLabel", font=("Segoe UI", 9, "bold")).grid(row=1, column=2, sticky="w", padx=(18, 8), pady=(10, 0))
        auth_combo = ttk.Combobox(connection, textvariable=self.auth_mode_var, values=("Password", "Private Key"), state="readonly", width=18)
        auth_combo.grid(row=1, column=3, sticky="ew", pady=(10, 0))
        auth_combo.bind("<<ComboboxSelected>>", lambda _event: self._update_auth_fields())

        self.password_label = ttk.Label(connection, text="PASSWORD", style="SSHCard.TLabel", font=("Segoe UI", 9, "bold"))
        self.password_label.grid(row=2, column=0, sticky="w", pady=(10, 0))
        self.password_entry = ttk.Entry(connection, textvariable=self.password_var, show="•")
        self.password_entry.grid(row=2, column=1, sticky="ew", padx=(8, 0), pady=(10, 0), ipady=4)

        self.key_label = ttk.Label(connection, text="PRIVATE KEY", style="SSHCard.TLabel", font=("Segoe UI", 9, "bold"))
        self.key_entry = ttk.Entry(connection, textvariable=self.key_path_var)
        self.key_button = ttk.Button(connection, text="BROWSE", style="SSHSecondary.TButton", command=self.browse_key)
        self.passphrase_label = ttk.Label(connection, text="KEY PASSPHRASE", style="SSHCard.TLabel", font=("Segoe UI", 9, "bold"))
        self.passphrase_entry = ttk.Entry(connection, textvariable=self.key_passphrase_var, show="•")

        options = ttk.Frame(connection, style="SSHCard.TFrame")
        options.grid(row=4, column=0, columnspan=4, sticky="ew", pady=(14, 0))
        ttk.Checkbutton(options, text="Verify known host key", variable=self.verify_host_key_var, style="SSH.TCheckbutton").pack(side="left")
        ttk.Label(options, text="Timeout", style="SSHCardMuted.TLabel").pack(side="left", padx=(18, 5))
        ttk.Entry(options, textvariable=self.timeout_var, width=6).pack(side="left")
        ttk.Label(options, text="seconds", style="SSHCardMuted.TLabel").pack(side="left", padx=(5, 0))
        self.connect_button = ttk.Button(options, text="CONNECT", style="SSHPrimary.TButton", command=self.connect)
        self.connect_button.pack(side="right")
        self.disconnect_button = ttk.Button(options, text="DISCONNECT", style="SSHSecondary.TButton", command=self.disconnect, state="disabled")
        self.disconnect_button.pack(side="right", padx=(0, 8))

        command_card = ttk.Frame(self, style="SSHCard.TFrame", padding=12)
        command_card.pack(fill="both", expand=True, padx=18, pady=(0, 18))
        command_card.columnconfigure(0, weight=1)
        command_card.rowconfigure(1, weight=1)

        command_row = ttk.Frame(command_card, style="SSHCard.TFrame")
        command_row.grid(row=0, column=0, sticky="ew", pady=(0, 10))
        command_row.columnconfigure(1, weight=1)
        ttk.Label(command_row, text="COMMAND", style="SSHCard.TLabel", font=("Segoe UI", 9, "bold")).grid(row=0, column=0, padx=(0, 10))
        self.command_entry = ttk.Entry(command_row, textvariable=self.command_var, state="disabled", font=("Consolas", 10))
        self.command_entry.grid(row=0, column=1, sticky="ew", ipady=5)
        self.command_entry.bind("<Return>", lambda _event: self.run_command())
        self.run_button = ttk.Button(command_row, text="RUN COMMAND", style="SSHPrimary.TButton", command=self.run_command, state="disabled")
        self.run_button.grid(row=0, column=2, padx=(10, 0))

        terminal_shell = ttk.Frame(command_card, style="SSHCard.TFrame")
        terminal_shell.grid(row=1, column=0, sticky="nsew")
        terminal_shell.columnconfigure(0, weight=1)
        terminal_shell.rowconfigure(0, weight=1)
        self.terminal = tk.Text(terminal_shell, bg="#06101A", fg="#DCEAF5", insertbackground="white", selectbackground=BLUE, font=("Consolas", 10), wrap="word", relief="flat", padx=12, pady=12)
        self.terminal.grid(row=0, column=0, sticky="nsew")
        terminal_scroll = ttk.Scrollbar(terminal_shell, orient="vertical", command=self.terminal.yview)
        terminal_scroll.grid(row=0, column=1, sticky="ns")
        self.terminal.configure(yscrollcommand=terminal_scroll.set)
        self.terminal.tag_configure("command", foreground=CYAN, font=("Consolas", 10, "bold"))
        self.terminal.tag_configure("error", foreground=DANGER)
        self.terminal.tag_configure("success", foreground=SUCCESS)
        self.terminal.configure(state="disabled")

        footer = ttk.Frame(command_card, style="SSHCard.TFrame")
        footer.grid(row=2, column=0, sticky="ew", pady=(10, 0))
        self.status_dot = tk.Label(footer, text="●", bg=CARD, fg=DANGER, font=("Segoe UI", 13))
        self.status_dot.pack(side="left")
        ttk.Label(footer, textvariable=self.status_var, style="SSHCardMuted.TLabel").pack(side="left", padx=(4, 0))
        ttk.Button(footer, text="CLEAR OUTPUT", style="SSHSecondary.TButton", command=self.clear_output).pack(side="right")
        ttk.Button(footer, text="SAVE OUTPUT", style="SSHSecondary.TButton", command=self.save_output).pack(side="right", padx=(0, 8))

    def _field(self, parent, label, variable, row, column, width=None):
        ttk.Label(parent, text=label, style="SSHCard.TLabel", font=("Segoe UI", 9, "bold")).grid(row=row, column=column, sticky="w", padx=(18 if column else 0, 8), pady=(10 if row else 0, 0))
        entry = ttk.Entry(parent, textvariable=variable, width=width)
        entry.grid(row=row, column=column + 1, sticky="ew", pady=(10 if row else 0, 0), ipady=4)
        return entry

    def _update_auth_fields(self):
        if self.auth_mode_var.get() == "Password":
            self.key_label.grid_remove(); self.key_entry.grid_remove(); self.key_button.grid_remove()
            self.passphrase_label.grid_remove(); self.passphrase_entry.grid_remove()
            self.password_label.grid(); self.password_entry.grid()
        else:
            self.password_label.grid_remove(); self.password_entry.grid_remove()
            self.key_label.grid(row=2, column=0, sticky="w", pady=(10, 0))
            self.key_entry.grid(row=2, column=1, columnspan=2, sticky="ew", padx=(8, 8), pady=(10, 0), ipady=4)
            self.key_button.grid(row=2, column=3, sticky="e", pady=(10, 0))
            self.passphrase_label.grid(row=3, column=0, sticky="w", pady=(10, 0))
            self.passphrase_entry.grid(row=3, column=1, sticky="ew", padx=(8, 0), pady=(10, 0), ipady=4)

    def browse_key(self):
        path = filedialog.askopenfilename(parent=self.master_root, title="Select SSH private key", filetypes=[("Private keys", "*.pem *.ppk *.key id_rsa id_ed25519"), ("All files", "*.*")])
        if path:
            self.key_path_var.set(path)

    def connect(self):
        if self.connecting or self.connected:
            return
        if paramiko is None:
            messagebox.showerror("Missing Dependency", "Paramiko is required. Install it with:\n\npython -m pip install paramiko", parent=self.master_root)
            return
        host = self.host_var.get().strip()
        username = self.username_var.get().strip()
        if not host or not username:
            messagebox.showwarning("Connection", "Enter the host/IP and username.", parent=self.master_root)
            return
        try:
            port = int(self.port_var.get())
            timeout = float(self.timeout_var.get())
            if not 1 <= port <= 65535 or timeout <= 0:
                raise ValueError
        except ValueError:
            messagebox.showwarning("Connection", "Enter a valid port and positive timeout.", parent=self.master_root)
            return
        if self.auth_mode_var.get() == "Private Key" and not Path(self.key_path_var.get()).is_file():
            messagebox.showwarning("Private Key", "Select a valid private key file.", parent=self.master_root)
            return

        config = {"host": host, "port": port, "username": username, "timeout": timeout, "auth": self.auth_mode_var.get(), "password": self.password_var.get(), "key": self.key_path_var.get(), "passphrase": self.key_passphrase_var.get(), "verify": self.verify_host_key_var.get()}
        self.connecting = True
        self.connect_button.configure(state="disabled")
        self.status_var.set(f"Connecting to {host}:{port}...")
        self.worker = threading.Thread(target=self._connect_worker, args=(config,), daemon=True)
        self.worker.start()

    def _connect_worker(self, config):
        client = paramiko.SSHClient()
        if config["verify"]:
            client.load_system_host_keys()
            client.set_missing_host_key_policy(paramiko.RejectPolicy())
        else:
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            kwargs = {"hostname": config["host"], "port": config["port"], "username": config["username"], "timeout": config["timeout"], "banner_timeout": config["timeout"], "auth_timeout": config["timeout"], "look_for_keys": False, "allow_agent": False}
            if config["auth"] == "Password":
                kwargs["password"] = config["password"]
            else:
                kwargs["key_filename"] = config["key"]
                kwargs["passphrase"] = config["passphrase"] or None
            client.connect(**kwargs)
            self.events.put(("connected", client, config["host"], config["username"]))
        except Exception as exc:
            client.close()
            self.events.put(("connect_error", str(exc)))

    def run_command(self):
        command = self.command_var.get().strip()
        if not self.connected or not command:
            return
        self.command_var.set("")
        self.run_button.configure(state="disabled")
        self.command_entry.configure(state="disabled")
        self._append(f"\n$ {command}\n", "command")
        threading.Thread(target=self._command_worker, args=(command,), daemon=True).start()

    def _command_worker(self, command):
        try:
            stdin, stdout, stderr = self.client.exec_command(command)
            stdin.close()
            output = stdout.read().decode("utf-8", errors="replace")
            error = stderr.read().decode("utf-8", errors="replace")
            exit_code = stdout.channel.recv_exit_status()
            self.events.put(("command_result", output, error, exit_code))
        except Exception as exc:
            self.events.put(("command_error", str(exc)))

    def disconnect(self):
        if self.client:
            self.client.close()
        self.client = None
        self.connected = False
        self.connecting = False
        self._set_connected_ui(False)
        self.status_var.set("Disconnected")
        self._append("\nDisconnected.\n", "error")

    def _set_connected_ui(self, connected):
        self.connected = connected
        self.connect_button.configure(state="disabled" if connected else "normal")
        self.disconnect_button.configure(state="normal" if connected else "disabled")
        self.command_entry.configure(state="normal" if connected else "disabled")
        self.run_button.configure(state="normal" if connected else "disabled")
        self.status_dot.configure(fg=SUCCESS if connected else DANGER)
        if connected:
            self.command_entry.focus_set()

    def _process_events(self):
        try:
            while True:
                event = self.events.get_nowait()
                kind = event[0]
                if kind == "connected":
                    self.client = event[1]
                    self.connecting = False
                    self._set_connected_ui(True)
                    self.status_var.set(f"Connected to {event[3]}@{event[2]}")
                    self._append(f"Connected to {event[3]}@{event[2]}\n", "success")
                elif kind == "connect_error":
                    self.connecting = False
                    self._set_connected_ui(False)
                    self.status_var.set("Connection failed")
                    self._append(f"Connection failed: {event[1]}\n", "error")
                elif kind == "command_result":
                    output, error, exit_code = event[1:]
                    if output: self._append(output)
                    if error: self._append(error, "error")
                    self._append(f"[exit code: {exit_code}]\n", "success" if exit_code == 0 else "error")
                    self.run_button.configure(state="normal")
                    self.command_entry.configure(state="normal")
                    self.command_entry.focus_set()
                elif kind == "command_error":
                    self._append(f"Command error: {event[1]}\n", "error")
                    self.run_button.configure(state="normal")
                    self.command_entry.configure(state="normal")
        except queue.Empty:
            pass
        if self.winfo_exists():
            self.after(100, self._process_events)

    def _append(self, text, tag=None):
        self.terminal.configure(state="normal")
        self.terminal.insert("end", text, tag or ())
        self.terminal.see("end")
        self.terminal.configure(state="disabled")

    def clear_output(self):
        self.terminal.configure(state="normal")
        self.terminal.delete("1.0", "end")
        self.terminal.configure(state="disabled")

    def save_output(self):
        target = filedialog.asksaveasfilename(parent=self.master_root, title="Save SSH output", defaultextension=".txt", filetypes=[("Text files", "*.txt")], initialfile="ssh-output.txt")
        if target:
            Path(target).write_text(self.terminal.get("1.0", "end-1c"), encoding="utf-8")

    def cleanup(self):
        if self.client:
            self.client.close()


def create_embedded_app(parent, master_root=None):
    """Required OSV Master GUI plug-in entrypoint."""
    return OSVSSHClient(parent, master_root=master_root)


def run_standalone():
    root = tk.Tk()
    root.title(APP_TITLE)
    root.geometry("1250x800")
    root.minsize(920, 650)
    OSVSSHClient(root, master_root=root)
    root.mainloop()


if __name__ == "__main__":
    run_standalone()
