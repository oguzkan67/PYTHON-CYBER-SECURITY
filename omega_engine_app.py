import customtkinter as ctk
import psutil, platform, datetime, socket, os, threading, csv
from pathlib import Path
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

class OmegaMonitor(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("NeonStats OMEGA v4.5 - Ultimate System Controller")
        self.geometry("1400x900") # Portlar için boyutu hafif büyüttüm
        ctk.set_appearance_mode("dark")
        
        self.cpu_history = [0] * 50
        self.net_io_prev = psutil.net_io_counters()
        self.disk_io_prev = psutil.disk_io_counters()
        self.is_logging = False
        
        self.init_interface()
        self.core_engine()

    def init_interface(self):
        self.grid_columnconfigure(1, weight=4)
        self.grid_rowconfigure(0, weight=1)

        # --- SIDEBAR (Senin Orijinal Sidebarın) ---
        self.sidebar = ctk.CTkFrame(self, width=250, corner_radius=0)
        self.sidebar.grid(row=0, column=0, sticky="nsew")
        
        ctk.CTkLabel(self.sidebar, text="OMEGA ENGINE", font=("Consolas", 24, "bold"), text_color="#00ffcc").pack(pady=30)
        
        self.add_stat("OS", platform.system() + " " + platform.release())
        self.add_stat("ARCH", platform.machine())
        self.add_stat("PROCESSOR", platform.processor().split(' ')[0])
        self.add_stat("VM DETECT", self.detect_vm())
        self.add_stat("USER", os.getlogin())
        
        self.log_btn = ctk.CTkButton(self.sidebar, text="Start CSV Logger", fg_color="#27ae60", command=self.toggle_log)
        self.log_btn.pack(pady=10, padx=20)
        self.kill_btn = ctk.CTkButton(self.sidebar, text="Kill High CPU Proc", fg_color="#c0392b", command=self.emergency_kill)
        self.kill_btn.pack(pady=10, padx=20)
        self.theme_btn = ctk.CTkButton(self.sidebar, text="Switch Theme", command=lambda: ctk.set_appearance_mode("light" if ctk.get_appearance_mode()=="Dark" else "dark"))
        self.theme_btn.pack(pady=10, padx=20)

        # --- MAIN SCROLLABLE DASHBOARD (Senin Orijinal Dashboardın) ---
        self.dash = ctk.CTkScrollableFrame(self, fg_color="transparent")
        self.dash.grid(row=0, column=1, sticky="nsew", padx=10, pady=10)

        self.fig, self.ax = plt.subplots(figsize=(10, 2.5), facecolor='#121212')
        self.ax.set_facecolor('#121212')
        self.line, = self.ax.plot(self.cpu_history, color='#00ffcc', linewidth=2)
        self.ax.axis('off')
        self.canvas = FigureCanvasTkAgg(self.fig, master=self.dash)
        self.canvas.get_tk_widget().pack(fill="x", pady=10)

        self.tile_frame = ctk.CTkFrame(self.dash, fg_color="transparent")
        self.tile_frame.pack(fill="both", expand=True)
        
        self.box_net = self.create_tile(self.tile_frame, "NETWORK THROUGHPUT", "D: 0 | U: 0", 0, 0)
        self.box_disk = self.create_tile(self.tile_frame, "DISK I/O SPEED", "R: 0 | W: 0", 0, 1)
        self.box_ram = self.create_tile(self.tile_frame, "RAM HEALTH", "0% Used", 1, 0)
        self.box_power = self.create_tile(self.tile_frame, "POWER STATUS", "N/A", 1, 1)
        self.box_sockets = self.create_tile(self.tile_frame, "ACTIVE SOCKETS", "0 Conn", 2, 0)
        self.box_boot = self.create_tile(self.tile_frame, "LAST BOOT", "--", 2, 1)

        # --- YENİ EKLENEN PORT ANALİZ KISMI ---
        ctk.CTkLabel(self.dash, text="LIVE PORT & SERVICE AUDIT", font=("Consolas", 16, "bold"), text_color="#f39c12").pack(pady=10)
        self.port_view = ctk.CTkTextbox(self.dash, height=200, font=("Consolas", 11), fg_color="#1a1a1a")
        self.port_view.pack(fill="x", padx=10, pady=5)

        # Alt Listeler (Orijinal Yapın)
        self.list_container = ctk.CTkFrame(self.dash, fg_color="transparent")
        self.list_container.pack(fill="both", expand=True, pady=20)
        
        self.proc_view = self.create_list_box(self.list_container, "TOP PROCESSES", "left")
        self.usb_view = self.create_list_box(self.list_container, "USB & DRIVES", "right")

    # --- YENİ FONKSİYON: PORT ANALİZİ ---
    def get_port_details(self):
        port_data = f"{'PROTO':<6} {'LOCAL ADDR':<20} {'STATUS':<15} {'SERVICE'}\n" + "-"*70 + "\n"
        try:
            for conn in psutil.net_connections(kind='inet')[:20]: # İlk 20 bağlantı
                l_addr = f"{conn.laddr.ip}:{conn.laddr.port}"
                try: service = socket.getservbyport(conn.laddr.port)
                except: service = "unknown"
                proto = "TCP" if conn.type == socket.SOCK_STREAM else "UDP"
                port_data += f"{proto:<6} {l_addr:<20} {conn.status:<15} {service}\n"
        except: port_data += "Access Denied (Run as Admin)"
        return port_data

    # --- SENİN DİĞER FONKSİYONLARIN (DOKUNULMADI) ---
    def add_stat(self, title, val):
        lbl = ctk.CTkLabel(self.sidebar, text=f"{title}: {val}", font=("Arial", 11), text_color="gray")
        lbl.pack(pady=2, padx=20, anchor="w")

    def create_tile(self, master, title, text, r, c):
        f = ctk.CTkFrame(master, height=100)
        f.grid(row=r, column=c, padx=10, pady=10, sticky="nsew")
        ctk.CTkLabel(f, text=title, font=("Arial", 10, "bold"), text_color="#00ffcc").pack(pady=5)
        l = ctk.CTkLabel(f, text=text, font=("Consolas", 14))
        l.pack(pady=10)
        return l

    def create_list_box(self, master, title, side):
        f = ctk.CTkFrame(master)
        f.pack(side=side, fill="both", expand=True, padx=5)
        ctk.CTkLabel(f, text=title, font=("Arial", 12, "bold")).pack(pady=5)
        box = ctk.CTkTextbox(f, height=250, font=("Consolas", 11))
        box.pack(fill="both", expand=True, padx=5, pady=5)
        return box

    def detect_vm(self):
        vm_markers = ['virtualbox', 'vmware', 'vbox', 'qemu', 'hyper-v']
        for p in psutil.process_iter(['name']):
            if any(m in p.info['name'].lower() for m in vm_markers): return "Detected"
        return "None"

    def get_usb(self):
        drives = ""
        for p in psutil.disk_partitions():
            try:
                usage = psutil.disk_usage(p.mountpoint)
                drives += f"{p.device} [{p.fstype}]\n└─ {p.mountpoint} ({usage.percent}% Full)\n"
            except: continue
        return drives if drives else "No drives found."

    def emergency_kill(self):
        for p in psutil.process_iter(['pid', 'name', 'cpu_percent']):
            if p.info['cpu_percent'] > 40:
                p.kill()

    def toggle_log(self):
        self.is_logging = not self.is_logging
        self.log_btn.configure(text="Logging..." if self.is_logging else "Start CSV Logger", fg_color="red" if self.is_logging else "#27ae60")

    def core_engine(self):
        try:
            cpu_p = psutil.cpu_percent()
            mem = psutil.virtual_memory()
            boot = datetime.datetime.fromtimestamp(psutil.boot_time()).strftime("%H:%M")
            batt = psutil.sensors_battery()
            
            # Net Speed
            net_now = psutil.net_io_counters()
            d_spd = (net_now.bytes_recv - self.net_io_prev.bytes_recv) / 1024
            u_spd = (net_now.bytes_sent - self.net_io_prev.bytes_sent) / 1024
            self.net_io_prev = net_now
            
            # Disk Speed
            disk_now = psutil.disk_io_counters()
            r_spd = (disk_now.read_bytes - self.disk_io_prev.read_bytes) / 1024 / 1024
            w_spd = (disk_now.write_bytes - self.disk_io_prev.write_bytes) / 1024 / 1024
            self.disk_io_prev = disk_now

            # UI Güncellemeleri
            self.box_net.configure(text=f"DL: {d_spd:.1f} KB/s\nUP: {u_spd:.1f} KB/s")
            self.box_disk.configure(text=f"Read: {r_spd:.1f} MB/s\nWrite: {w_spd:.1f} MB/s")
            self.box_ram.configure(text=f"{mem.percent}% Used\n({mem.available // (1024**2)}MB Free)")
            self.box_sockets.configure(text=f"{len(psutil.net_connections())} Connections")
            self.box_boot.configure(text=boot)
            
            if batt:
                self.box_power.configure(text=f"{batt.percent}% [{'AC' if batt.power_plugged else 'DC'}]")

            # PORT ANALİZ GÜNCELLEME (Yeni Eklenen)
            self.port_view.delete("1.0", "end")
            self.port_view.insert("end", self.get_port_details())

            # Diğer Listeler
            p_txt = "PID   CPU%   NAME\n" + "-"*25 + "\n"
            for p in sorted(psutil.process_iter(['pid', 'name', 'cpu_percent']), key=lambda x: x.info['cpu_percent'], reverse=True)[:10]:
                p_txt += f"{p.info['pid']:<6} {p.info['cpu_percent']:<6} {p.info['name']}\n"
            self.proc_view.delete("1.0", "end"); self.proc_view.insert("end", p_txt)
            self.usb_view.delete("1.0", "end"); self.usb_view.insert("end", self.get_usb())

            self.cpu_history.pop(0); self.cpu_history.append(cpu_p)
            self.line.set_ydata(self.cpu_history); self.canvas.draw()
            
            if self.is_logging:
                with open("omega_log.csv", "a") as f:
                    csv.writer(f).writerow([datetime.datetime.now(), cpu_p, mem.percent])

        except Exception as e: print(f"Engine Error: {e}")
        self.after(1000, self.core_engine)

if __name__ == "__main__":
    app = OmegaMonitor()
    app.mainloop()
