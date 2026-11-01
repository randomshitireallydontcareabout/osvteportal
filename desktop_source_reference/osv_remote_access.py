#!/usr/bin/env python3
"""OSV Remote Access Hub: SSH command client and Windows RDP jumpbox launcher."""

import ctypes
import json
import os
import queue
import subprocess
import threading
import tkinter as tk
from ctypes import wintypes
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

try:
    import keyring
except ImportError:
    keyring = None

try:
    import paramiko
except ImportError:
    paramiko = None

APP_TITLE = "OSV Remote Access Hub"
APP_DIR = Path(os.environ.get("APPDATA", Path.home())) / "OSVRemoteAccess"
PROFILES_FILE = APP_DIR / "profiles.json"
KEYRING_SERVICE = "OSV Remote Access Hub"

BG = "#07111D"
PANEL = "#0A1A2A"
CARD = "#0D2235"
CARD_2 = "#102A40"
LINE = "#173A55"
BLUE = "#0D7CC1"
CYAN = "#22B8EE"
TEXT = "#F3F7FB"
MUTED = "#9BB3C7"
SUCCESS = "#3DD6A1"
DANGER = "#FF6B6B"


class GradientHeader(tk.Canvas):
    def __init__(self, parent, start="#07111D", end="#07517A", **kwargs):
        kwargs.setdefault("highlightthickness", 0)
        kwargs.setdefault("borderwidth", 0)
        kwargs.setdefault("bg", start)
        super().__init__(parent, **kwargs)
        self.start_color = start
        self.end_color = end
        self.bind("<Configure>", self._draw, add="+")

    def _rgb(self, color):
        r, g, b = self.winfo_rgb(color)
        return r // 256, g // 256, b // 256

    def _draw(self, _event=None):
        self.delete("gradient")
        width = max(self.winfo_width(), 1)
        height = max(self.winfo_height(), 1)
        start = self._rgb(self.start_color)
        end = self._rgb(self.end_color)
        for x in range(width):
            ratio = x / max(width - 1, 1)
            rgb = [int(start[i] + (end[i] - start[i]) * ratio) for i in range(3)]
            self.create_line(x, 0, x, height, fill="#{:02x}{:02x}{:02x}".format(*rgb), tags="gradient")
        self.tag_lower("gradient")


class CredentialBlob(ctypes.Structure):
    _fields_ = [("Flags", wintypes.DWORD), ("Type", wintypes.DWORD),
                ("TargetName", wintypes.LPWSTR), ("Comment", wintypes.LPWSTR),
                ("LastWritten", wintypes.FILETIME), ("CredentialBlobSize", wintypes.DWORD),
                ("CredentialBlob", ctypes.POINTER(ctypes.c_ubyte)),
                ("Persist", wintypes.DWORD), ("AttributeCount", wintypes.DWORD),
                ("Attributes", wintypes.LPVOID), ("TargetAlias", wintypes.LPWSTR),
                ("UserName", wintypes.LPWSTR)]


def save_windows_rdp_credential(host, username, password):
    """Write an RDP credential directly to Windows Credential Manager."""
    if os.name != "nt":
        raise RuntimeError("RDP credential storage is available only on Windows.")
    target = f"TERMSRV/{host}"
    encoded = password.encode("utf-16-le")
    blob = (ctypes.c_ubyte * len(encoded)).from_buffer_copy(encoded)
    credential = CredentialBlob()
    credential.Type = 1  # CRED_TYPE_GENERIC
    credential.TargetName = target
    credential.CredentialBlobSize = len(encoded)
    credential.CredentialBlob = ctypes.cast(blob, ctypes.POINTER(ctypes.c_ubyte))
    credential.Persist = 2  # CRED_PERSIST_LOCAL_MACHINE
    credential.UserName = username
    if not ctypes.windll.advapi32.CredWriteW(ctypes.byref(credential), 0):
        raise ctypes.WinError()


def delete_windows_rdp_credential(host):
    if os.name == "nt":
        ctypes.windll.advapi32.CredDeleteW(f"TERMSRV/{host}", 1, 0)


class ProfileStore:
    def __init__(self):
        APP_DIR.mkdir(parents=True, exist_ok=True)
        self.profiles = self._load()

    def _load(self):
        try:
            value = json.loads(PROFILES_FILE.read_text(encoding="utf-8"))
            return value if isinstance(value, list) else []
        except (OSError, json.JSONDecodeError):
            return []

    def save(self):
        PROFILES_FILE.write_text(json.dumps(self.profiles, indent=2), encoding="utf-8")

    def upsert(self, profile):
        self.profiles = [item for item in self.profiles if item.get("name") != profile["name"]]
        self.profiles.append(profile)
        self.profiles.sort(key=lambda item: item.get("name", "").lower())
        self.save()

    def delete(self, name):
        self.profiles = [item for item in self.profiles if item.get("name") != name]
        self.save()


class RemoteAccessApp(tk.Frame):
    def __init__(self, parent, master_root=None):
        self.master_root = master_root or parent.winfo_toplevel()
        super().__init__(parent, bg=BG)
        self.pack(fill="both", expand=True)
        self.store = ProfileStore()
        self.client = None
        self.connected = False
        self.events = queue.Queue()
        self._build_variables()
        self._style()
        self._build()
        self.refresh_profiles()
        self.after(100, self._process_events)

    def _build_variables(self):
        self.ssh_host = tk.StringVar(); self.ssh_port = tk.StringVar(value="22")
        self.ssh_user = tk.StringVar(); self.ssh_password = tk.StringVar()
        self.ssh_auth = tk.StringVar(value="Password"); self.ssh_key = tk.StringVar()
        self.ssh_passphrase = tk.StringVar(); self.ssh_command = tk.StringVar()
        self.ssh_verify = tk.BooleanVar(value=True); self.ssh_save = tk.BooleanVar(value=True)
        self.ssh_profile = tk.StringVar(); self.ssh_status = tk.StringVar(value="Disconnected")
        self.rdp_host = tk.StringVar(); self.rdp_port = tk.StringVar(value="3389")
        self.rdp_user = tk.StringVar(); self.rdp_password = tk.StringVar()
        self.rdp_domain = tk.StringVar(); self.rdp_fullscreen = tk.BooleanVar(value=False)
        self.rdp_admin = tk.BooleanVar(value=False); self.rdp_save = tk.BooleanVar(value=True)
        self.rdp_profile = tk.StringVar(); self.rdp_status = tk.StringVar(value="Ready")

    def _style(self):
        s = ttk.Style(self); s.theme_use("clam")
        s.configure("RA.TFrame", background=BG); s.configure("RACard.TFrame", background=CARD)
        s.configure("RA.TLabel", background=BG, foreground=TEXT)
        s.configure("RAMuted.TLabel", background=BG, foreground=MUTED)
        s.configure("RACard.TLabel", background=CARD, foreground=TEXT)
        s.configure("RACardMuted.TLabel", background=CARD, foreground=MUTED)
        s.configure("RA.TCheckbutton", background=CARD, foreground=TEXT, focuscolor=CARD)
        s.configure("RAPrimary.TButton", background=BLUE, foreground="white", padding=(14, 9), font=("Segoe UI", 10, "bold"))
        s.map("RAPrimary.TButton", background=[("active", CYAN), ("disabled", "#31506A")])
        s.configure("RASecondary.TButton", background=LINE, foreground=TEXT, padding=(12, 8))
        s.map("RASecondary.TButton", background=[("active", "#245878")])
        s.configure("Danger.TButton", background="#8E3440", foreground="white", padding=(12, 8))
        s.configure("TNotebook", background=BG, borderwidth=0)
        s.configure("TNotebook.Tab", background=CARD, foreground=MUTED, padding=(24, 12), font=("Segoe UI", 10, "bold"))
        s.map("TNotebook.Tab", background=[("selected", BLUE), ("active", CARD_2)], foreground=[("selected", "white"), ("active", "white")])
        s.configure("Profiles.Treeview", background="#091725", fieldbackground="#091725", foreground=TEXT, rowheight=30, borderwidth=0)
        s.configure("Profiles.Treeview.Heading", background=CARD_2, foreground=TEXT, font=("Segoe UI", 10, "bold"))
        s.map("Profiles.Treeview", background=[("selected", BLUE)], foreground=[("selected", "white")])

    def _build(self):
        header = GradientHeader(self, height=96); header.pack(fill="x", padx=18, pady=(18, 12)); header.pack_propagate(False)
        inner = tk.Frame(header, bg=PANEL); inner.pack(fill="both", expand=True, padx=5, pady=5)
        tk.Frame(inner, bg=CYAN, width=5).pack(side="left", fill="y")
        copy = tk.Frame(inner, bg=PANEL); copy.pack(side="left", fill="both", expand=True, padx=20, pady=12)
        tk.Label(copy, text=APP_TITLE, bg=PANEL, fg=TEXT, font=("Segoe UI", 25, "bold")).pack(anchor="w")
        tk.Label(copy, text="SSH commands and Windows RDP jumpbox access in one secure OSV workspace.", bg=PANEL, fg=MUTED, font=("Segoe UI", 10)).pack(anchor="w", pady=(4, 0))
        badge = tk.Label(inner, text="SECURE CREDENTIAL VAULT", bg="#0A4669", fg=CYAN, font=("Segoe UI", 9, "bold"), padx=14, pady=7)
        badge.pack(side="right", padx=18)

        self.tabs = ttk.Notebook(self); self.tabs.pack(fill="both", expand=True, padx=18, pady=(0, 18))
        self.ssh_tab = ttk.Frame(self.tabs, style="RA.TFrame", padding=12)
        self.rdp_tab = ttk.Frame(self.tabs, style="RA.TFrame", padding=12)
        self.profile_tab = ttk.Frame(self.tabs, style="RA.TFrame", padding=12)
        self.tabs.add(self.ssh_tab, text="  SSH TERMINAL  ")
        self.tabs.add(self.rdp_tab, text="  RDP JUMPBOX  ")
        self.tabs.add(self.profile_tab, text="  SAVED CONNECTIONS  ")
        self._build_ssh(); self._build_rdp(); self._build_profiles()

    def _entry(self, parent, label, var, row, col, show=None, width=None):
        ttk.Label(parent, text=label, style="RACard.TLabel", font=("Segoe UI", 9, "bold")).grid(row=row, column=col, sticky="w", padx=(14 if col else 0, 8), pady=(10 if row else 0, 0))
        entry = ttk.Entry(parent, textvariable=var, show=show, width=width)
        entry.grid(row=row, column=col + 1, sticky="ew", pady=(10 if row else 0, 0), ipady=4)
        return entry

    def _build_ssh(self):
        self.ssh_tab.columnconfigure(0, weight=1); self.ssh_tab.rowconfigure(1, weight=1)
        card = ttk.Frame(self.ssh_tab, style="RACard.TFrame", padding=16); card.grid(row=0, column=0, sticky="ew", pady=(0, 10))
        card.columnconfigure(1, weight=1); card.columnconfigure(3, weight=1)
        self._entry(card, "HOST / IP", self.ssh_host, 0, 0); self._entry(card, "PORT", self.ssh_port, 0, 2, width=7)
        self._entry(card, "USERNAME", self.ssh_user, 1, 0)
        ttk.Label(card, text="AUTHENTICATION", style="RACard.TLabel", font=("Segoe UI", 9, "bold")).grid(row=1, column=2, sticky="w", padx=(14, 8), pady=(10, 0))
        auth = ttk.Combobox(card, textvariable=self.ssh_auth, values=("Password", "Private Key"), state="readonly")
        auth.grid(row=1, column=3, sticky="ew", pady=(10, 0)); auth.bind("<<ComboboxSelected>>", lambda _e: self._toggle_ssh_auth())
        self.ssh_password_label = ttk.Label(card, text="PASSWORD", style="RACard.TLabel", font=("Segoe UI", 9, "bold")); self.ssh_password_label.grid(row=2, column=0, sticky="w", pady=(10, 0))
        self.ssh_password_entry = ttk.Entry(card, textvariable=self.ssh_password, show="•"); self.ssh_password_entry.grid(row=2, column=1, sticky="ew", padx=(8, 0), pady=(10, 0), ipady=4)
        self.ssh_key_label = ttk.Label(card, text="PRIVATE KEY", style="RACard.TLabel", font=("Segoe UI", 9, "bold")); self.ssh_key_entry = ttk.Entry(card, textvariable=self.ssh_key)
        self.ssh_key_button = ttk.Button(card, text="BROWSE", style="RASecondary.TButton", command=self.browse_key)
        self.ssh_phrase_label = ttk.Label(card, text="KEY PASSPHRASE", style="RACard.TLabel", font=("Segoe UI", 9, "bold")); self.ssh_phrase_entry = ttk.Entry(card, textvariable=self.ssh_passphrase, show="•")
        options = ttk.Frame(card, style="RACard.TFrame"); options.grid(row=4, column=0, columnspan=4, sticky="ew", pady=(14, 0))
        ttk.Checkbutton(options, text="Verify known host key", variable=self.ssh_verify, style="RA.TCheckbutton").pack(side="left")
        ttk.Checkbutton(options, text="Save connection and credential", variable=self.ssh_save, style="RA.TCheckbutton").pack(side="left", padx=18)
        self.ssh_connect = ttk.Button(options, text="CONNECT", style="RAPrimary.TButton", command=self.connect_ssh); self.ssh_connect.pack(side="right")
        self.ssh_disconnect = ttk.Button(options, text="DISCONNECT", style="RASecondary.TButton", command=self.disconnect_ssh, state="disabled"); self.ssh_disconnect.pack(side="right", padx=8)
        self._toggle_ssh_auth()

        terminal_card = ttk.Frame(self.ssh_tab, style="RACard.TFrame", padding=12); terminal_card.grid(row=1, column=0, sticky="nsew")
        terminal_card.columnconfigure(0, weight=1); terminal_card.rowconfigure(1, weight=1)
        row = ttk.Frame(terminal_card, style="RACard.TFrame"); row.grid(row=0, column=0, sticky="ew", pady=(0, 10)); row.columnconfigure(1, weight=1)
        ttk.Label(row, text="COMMAND", style="RACard.TLabel", font=("Segoe UI", 9, "bold")).grid(row=0, column=0, padx=(0, 10))
        self.command_entry = ttk.Entry(row, textvariable=self.ssh_command, state="disabled", font=("Consolas", 10)); self.command_entry.grid(row=0, column=1, sticky="ew", ipady=5); self.command_entry.bind("<Return>", lambda _e: self.run_command())
        self.run_button = ttk.Button(row, text="RUN COMMAND", style="RAPrimary.TButton", state="disabled", command=self.run_command); self.run_button.grid(row=0, column=2, padx=(10, 0))
        terminal_shell = ttk.Frame(terminal_card, style="RACard.TFrame")
        terminal_shell.grid(row=1, column=0, sticky="nsew")
        terminal_shell.columnconfigure(0, weight=1)
        terminal_shell.rowconfigure(0, weight=1)
        self.terminal = tk.Text(terminal_shell, bg="#06101A", fg="#DCEAF5", insertbackground="white", selectbackground=BLUE, font=("Consolas", 10), wrap="word", relief="flat", padx=12, pady=12)
        self.terminal.grid(row=0, column=0, sticky="nsew")
        terminal_scroll = ttk.Scrollbar(terminal_shell, orient="vertical", command=self.terminal.yview)
        terminal_scroll.grid(row=0, column=1, sticky="ns")
        self.terminal.configure(yscrollcommand=terminal_scroll.set, state="disabled")
        self.terminal.tag_configure("command", foreground=CYAN, font=("Consolas", 10, "bold")); self.terminal.tag_configure("error", foreground=DANGER); self.terminal.tag_configure("success", foreground=SUCCESS)
        footer = ttk.Frame(terminal_card, style="RACard.TFrame"); footer.grid(row=2, column=0, sticky="ew", pady=(10, 0))
        self.ssh_dot = tk.Label(footer, text="●", bg=CARD, fg=DANGER, font=("Segoe UI", 13)); self.ssh_dot.pack(side="left")
        ttk.Label(footer, textvariable=self.ssh_status, style="RACardMuted.TLabel").pack(side="left", padx=5)
        ttk.Button(footer, text="CLEAR", style="RASecondary.TButton", command=self.clear_output).pack(side="right")

    def _build_rdp(self):
        self.rdp_tab.columnconfigure(0, weight=1)
        card = ttk.Frame(self.rdp_tab, style="RACard.TFrame", padding=20); card.grid(row=0, column=0, sticky="ew", pady=(0, 12)); card.columnconfigure(1, weight=1); card.columnconfigure(3, weight=1)
        ttk.Label(card, text="RDP JUMPBOX CONNECTION", style="RACard.TLabel", font=("Segoe UI", 16, "bold")).grid(row=0, column=0, columnspan=4, sticky="w", pady=(0, 14))
        self._entry(card, "HOST / IP", self.rdp_host, 1, 0); self._entry(card, "RDP PORT", self.rdp_port, 1, 2, width=8)
        self._entry(card, "USERNAME", self.rdp_user, 2, 0); self._entry(card, "DOMAIN (OPTIONAL)", self.rdp_domain, 2, 2)
        self._entry(card, "PASSWORD", self.rdp_password, 3, 0, show="•")
        opts = ttk.Frame(card, style="RACard.TFrame"); opts.grid(row=4, column=0, columnspan=4, sticky="ew", pady=(18, 0))
        ttk.Checkbutton(opts, text="Full screen", variable=self.rdp_fullscreen, style="RA.TCheckbutton").pack(side="left")
        ttk.Checkbutton(opts, text="Administrative session", variable=self.rdp_admin, style="RA.TCheckbutton").pack(side="left", padx=18)
        ttk.Checkbutton(opts, text="Save connection and credential", variable=self.rdp_save, style="RA.TCheckbutton").pack(side="left")
        ttk.Button(opts, text="LAUNCH RDP", style="RAPrimary.TButton", command=self.launch_rdp).pack(side="right")
        info = ttk.Frame(self.rdp_tab, style="RACard.TFrame", padding=20); info.grid(row=1, column=0, sticky="ew")
        ttk.Label(info, text="Secure credential handling", style="RACard.TLabel", font=("Segoe UI", 14, "bold")).pack(anchor="w")
        ttk.Label(info, text="RDP passwords are written directly to Windows Credential Manager under TERMSRV/<host>. Passwords are never placed in the profile JSON or passed through a command-line argument.", style="RACardMuted.TLabel", wraplength=900, justify="left").pack(anchor="w", pady=(8, 12))
        self.rdp_dot = tk.Label(info, text="●", bg=CARD, fg=SUCCESS, font=("Segoe UI", 13)); self.rdp_dot.pack(side="left")
        ttk.Label(info, textvariable=self.rdp_status, style="RACardMuted.TLabel").pack(side="left", padx=5)

    def _build_profiles(self):
        self.profile_tab.columnconfigure(0, weight=1); self.profile_tab.rowconfigure(0, weight=1)
        card = ttk.Frame(self.profile_tab, style="RACard.TFrame", padding=12); card.grid(row=0, column=0, sticky="nsew"); card.columnconfigure(0, weight=1); card.rowconfigure(0, weight=1)
        columns = ("name", "type", "host", "port", "username")
        self.profile_tree = ttk.Treeview(card, columns=columns, show="headings", style="Profiles.Treeview")
        for name, title, width in (("name", "Profile", 230), ("type", "Type", 80), ("host", "Host / IP", 260), ("port", "Port", 75), ("username", "Username", 240)):
            self.profile_tree.heading(name, text=title); self.profile_tree.column(name, width=width, anchor="w", stretch=name in {"name", "host", "username"})
        self.profile_tree.grid(row=0, column=0, sticky="nsew"); scroll = ttk.Scrollbar(card, command=self.profile_tree.yview); scroll.grid(row=0, column=1, sticky="ns"); self.profile_tree.configure(yscrollcommand=scroll.set)
        self.profile_tree.bind("<Double-1>", lambda _e: self.load_profile())
        buttons = ttk.Frame(card, style="RACard.TFrame"); buttons.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(10, 0))
        ttk.Button(buttons, text="LOAD SELECTED", style="RAPrimary.TButton", command=self.load_profile).pack(side="left")
        ttk.Button(buttons, text="DELETE PROFILE", style="Danger.TButton", command=self.delete_profile).pack(side="left", padx=8)
        ttk.Button(buttons, text="REFRESH", style="RASecondary.TButton", command=self.refresh_profiles).pack(side="right")

    def _toggle_ssh_auth(self):
        if self.ssh_auth.get() == "Password":
            for widget in (self.ssh_key_label, self.ssh_key_entry, self.ssh_key_button, self.ssh_phrase_label, self.ssh_phrase_entry): widget.grid_remove()
            self.ssh_password_label.grid(); self.ssh_password_entry.grid()
        else:
            self.ssh_password_label.grid_remove(); self.ssh_password_entry.grid_remove()
            self.ssh_key_label.grid(row=2, column=0, sticky="w", pady=(10, 0)); self.ssh_key_entry.grid(row=2, column=1, columnspan=2, sticky="ew", padx=(8, 8), pady=(10, 0), ipady=4); self.ssh_key_button.grid(row=2, column=3, pady=(10, 0))
            self.ssh_phrase_label.grid(row=3, column=0, sticky="w", pady=(10, 0)); self.ssh_phrase_entry.grid(row=3, column=1, sticky="ew", padx=(8, 0), pady=(10, 0), ipady=4)

    def browse_key(self):
        path = filedialog.askopenfilename(parent=self.master_root, title="Select SSH private key", filetypes=[("Private keys", "*.pem *.key *.ppk id_rsa id_ed25519"), ("All files", "*.*")])
        if path: self.ssh_key.set(path)

    def credential_key(self, kind, host, username):
        return f"{kind}|{host}|{username}"

    def save_secret(self, kind, host, username, secret):
        if not secret: return
        if keyring is None: raise RuntimeError("Install the keyring package to save SSH credentials securely.")
        keyring.set_password(KEYRING_SERVICE, self.credential_key(kind, host, username), secret)

    def get_secret(self, kind, host, username):
        if keyring is None: return ""
        return keyring.get_password(KEYRING_SERVICE, self.credential_key(kind, host, username)) or ""

    def save_profile(self, profile, secret=""):
        self.store.upsert(profile)
        if profile["type"] == "SSH" and secret: self.save_secret("SSH", profile["host"], profile["username"], secret)
        elif profile["type"] == "RDP" and secret: save_windows_rdp_credential(profile["host"], profile["username"], secret)
        self.refresh_profiles()

    def connect_ssh(self):
        if paramiko is None:
            messagebox.showerror("Missing Dependency", "Install required packages with:\n\npython -m pip install -r requirements.txt", parent=self.master_root); return
        host = self.ssh_host.get().strip(); user = self.ssh_user.get().strip()
        if not host or not user: messagebox.showwarning("SSH", "Enter the host/IP and username.", parent=self.master_root); return
        try: port = int(self.ssh_port.get())
        except ValueError: messagebox.showwarning("SSH", "Enter a valid SSH port.", parent=self.master_root); return
        password = self.ssh_password.get() if self.ssh_auth.get() == "Password" else self.ssh_passphrase.get()
        profile = {"name": f"SSH - {host} - {user}", "type": "SSH", "host": host, "port": port, "username": user, "auth": self.ssh_auth.get(), "key": self.ssh_key.get(), "verify": self.ssh_verify.get()}
        if self.ssh_save.get():
            try: self.save_profile(profile, password)
            except Exception as exc: messagebox.showerror("Credential Storage", str(exc), parent=self.master_root); return
        config = dict(profile); config["password"] = self.ssh_password.get(); config["passphrase"] = self.ssh_passphrase.get()
        self.ssh_connect.configure(state="disabled"); self.ssh_status.set(f"Connecting to {host}...")
        threading.Thread(target=self._ssh_connect_worker, args=(config,), daemon=True).start()

    def _ssh_connect_worker(self, config):
        client = paramiko.SSHClient(); client.load_system_host_keys()
        client.set_missing_host_key_policy(paramiko.RejectPolicy() if config["verify"] else paramiko.AutoAddPolicy())
        try:
            kwargs = {"hostname": config["host"], "port": config["port"], "username": config["username"], "timeout": 12, "banner_timeout": 12, "auth_timeout": 12, "look_for_keys": False, "allow_agent": False}
            if config["auth"] == "Password": kwargs["password"] = config["password"]
            else: kwargs.update(key_filename=config["key"], passphrase=config["passphrase"] or None)
            client.connect(**kwargs); self.events.put(("ssh_connected", client, config))
        except Exception as exc: client.close(); self.events.put(("ssh_error", str(exc)))

    def run_command(self):
        command = self.ssh_command.get().strip()
        if not self.connected or not command: return
        self.ssh_command.set(""); self.command_entry.configure(state="disabled"); self.run_button.configure(state="disabled"); self._append(f"\n$ {command}\n", "command")
        threading.Thread(target=self._command_worker, args=(command,), daemon=True).start()

    def _command_worker(self, command):
        try:
            stdin, stdout, stderr = self.client.exec_command(command); stdin.close()
            output = stdout.read().decode("utf-8", errors="replace"); error = stderr.read().decode("utf-8", errors="replace"); code = stdout.channel.recv_exit_status()
            self.events.put(("command_result", output, error, code))
        except Exception as exc: self.events.put(("command_error", str(exc)))

    def disconnect_ssh(self):
        if self.client: self.client.close()
        self.client = None; self.connected = False; self._ssh_ui(False); self.ssh_status.set("Disconnected"); self._append("\nDisconnected.\n", "error")

    def _ssh_ui(self, connected):
        self.connected = connected; self.ssh_connect.configure(state="disabled" if connected else "normal"); self.ssh_disconnect.configure(state="normal" if connected else "disabled"); self.command_entry.configure(state="normal" if connected else "disabled"); self.run_button.configure(state="normal" if connected else "disabled"); self.ssh_dot.configure(fg=SUCCESS if connected else DANGER)
        if connected: self.command_entry.focus_set()

    def launch_rdp(self):
        if os.name != "nt": messagebox.showerror("RDP", "The built-in RDP launcher requires Windows.", parent=self.master_root); return
        host = self.rdp_host.get().strip(); user = self.rdp_user.get().strip(); password = self.rdp_password.get()
        if not host or not user: messagebox.showwarning("RDP", "Enter the jumpbox host/IP and username.", parent=self.master_root); return
        try: port = int(self.rdp_port.get())
        except ValueError: messagebox.showwarning("RDP", "Enter a valid RDP port.", parent=self.master_root); return
        full_user = f"{self.rdp_domain.get().strip()}\\{user}" if self.rdp_domain.get().strip() else user
        profile = {"name": f"RDP - {host} - {full_user}", "type": "RDP", "host": host, "port": port, "username": full_user, "domain": self.rdp_domain.get().strip(), "fullscreen": self.rdp_fullscreen.get(), "admin": self.rdp_admin.get()}
        try:
            if self.rdp_save.get(): self.save_profile(profile, password)
            args = ["mstsc.exe", f"/v:{host}:{port}"]
            if self.rdp_fullscreen.get(): args.append("/f")
            if self.rdp_admin.get(): args.append("/admin")
            subprocess.Popen(args); self.rdp_status.set(f"RDP launched for {host}")
        except Exception as exc: messagebox.showerror("RDP", str(exc), parent=self.master_root)

    def refresh_profiles(self):
        if not hasattr(self, "profile_tree"): return
        self.profile_tree.delete(*self.profile_tree.get_children())
        for index, item in enumerate(self.store.profiles): self.profile_tree.insert("", "end", iid=str(index), values=(item.get("name"), item.get("type"), item.get("host"), item.get("port"), item.get("username")))

    def selected_profile(self):
        selected = self.profile_tree.selection()
        if not selected: messagebox.showinfo("Saved Connections", "Select a profile first.", parent=self.master_root); return None
        return self.store.profiles[int(selected[0])]

    def load_profile(self):
        item = self.selected_profile()
        if not item: return
        if item["type"] == "SSH":
            self.ssh_host.set(item.get("host", "")); self.ssh_port.set(str(item.get("port", 22))); self.ssh_user.set(item.get("username", "")); self.ssh_auth.set(item.get("auth", "Password")); self.ssh_key.set(item.get("key", "")); self.ssh_verify.set(item.get("verify", True)); self._toggle_ssh_auth()
            secret = self.get_secret("SSH", item.get("host", ""), item.get("username", "")); (self.ssh_password if self.ssh_auth.get() == "Password" else self.ssh_passphrase).set(secret); self.tabs.select(self.ssh_tab)
        else:
            self.rdp_host.set(item.get("host", "")); self.rdp_port.set(str(item.get("port", 3389))); username = item.get("username", ""); domain = item.get("domain", ""); self.rdp_domain.set(domain); self.rdp_user.set(username.split("\\", 1)[-1] if domain else username); self.rdp_fullscreen.set(item.get("fullscreen", False)); self.rdp_admin.set(item.get("admin", False)); self.tabs.select(self.rdp_tab)

    def delete_profile(self):
        item = self.selected_profile()
        if not item: return
        if not messagebox.askyesno("Delete Profile", f"Delete {item['name']} and its saved credential?", parent=self.master_root): return
        try:
            if item["type"] == "SSH" and keyring is not None: keyring.delete_password(KEYRING_SERVICE, self.credential_key("SSH", item["host"], item["username"]))
            elif item["type"] == "RDP": delete_windows_rdp_credential(item["host"])
        except Exception: pass
        self.store.delete(item["name"]); self.refresh_profiles()

    def _process_events(self):
        try:
            while True:
                event = self.events.get_nowait(); kind = event[0]
                if kind == "ssh_connected": self.client = event[1]; self._ssh_ui(True); self.ssh_status.set(f"Connected to {event[2]['username']}@{event[2]['host']}"); self._append(f"Connected to {event[2]['username']}@{event[2]['host']}\n", "success")
                elif kind == "ssh_error": self._ssh_ui(False); self.ssh_status.set("Connection failed"); self._append(f"Connection failed: {event[1]}\n", "error")
                elif kind == "command_result":
                    if event[1]: self._append(event[1])
                    if event[2]: self._append(event[2], "error")
                    self._append(f"[exit code: {event[3]}]\n", "success" if event[3] == 0 else "error"); self.command_entry.configure(state="normal"); self.run_button.configure(state="normal"); self.command_entry.focus_set()
                elif kind == "command_error": self._append(f"Command error: {event[1]}\n", "error"); self.command_entry.configure(state="normal"); self.run_button.configure(state="normal")
        except queue.Empty: pass
        if self.winfo_exists(): self.after(100, self._process_events)

    def _append(self, text, tag=None):
        self.terminal.configure(state="normal"); self.terminal.insert("end", text, tag or ()); self.terminal.see("end"); self.terminal.configure(state="disabled")

    def clear_output(self):
        self.terminal.configure(state="normal"); self.terminal.delete("1.0", "end"); self.terminal.configure(state="disabled")

    def cleanup(self):
        if self.client: self.client.close()


def create_embedded_app(parent, master_root=None):
    return RemoteAccessApp(parent, master_root=master_root)


def run_standalone():
    root = tk.Tk(); root.title(APP_TITLE); root.geometry("1300x840"); root.minsize(980, 680); RemoteAccessApp(root, root); root.mainloop()


if __name__ == "__main__":
    run_standalone()
