import tkinter as tk
from tkinter import ttk, filedialog, messagebox, simpledialog, scrolledtext
import re
import csv
from datetime import datetime
import urllib.parse
import html
import os
from collections import Counter

# External libraries
try:
    from fpdf import FPDF
    import matplotlib.pyplot as plt
    import matplotlib.dates as mdates
    plt.style.use('dark_background')
except ImportError:
    print("Please install required libraries: pip install fpdf matplotlib")
    exit()

# --- 1. CONFIGURATION & THREAT INTELLIGENCE ---

THREAT_INTEL_IOCS = [
    "192.168.1.100", "10.0.0.50", "45.33.22.11", "103.21.244.0"
]

AUTO_BLOCK_LIST = set()

# --- EXTENDED RULESET (30+ Rules) ---
DEFAULT_RULES = {
    "SQL Injection - Generic": r"(union\s+select|select\s+\*|drop\s+table|--|;|\bOR\b.+=\s*.+)",
    "SQLi - Tautology": r"(\bOR\b\s+\d+=\d+|'='|' OR '1'='1|1=1)",
    "SQLi - Blind Time-Based": r"(sleep\(|benchmark\(|pg_sleep|waitfor delay)",
    "SQLi - Union Based": r"(union\s+all\s+select|union\s+select)",
    "SQLi - Error Based": r"(syntax\s+error|unclosed\s+quotation\s+mark|mysql_fetch)",
    
    "XSS - Script Tag": r"(<script\b|javascript:|onerror=|onload=|alert\()",
    "XSS - Event Handlers": r"(onmouseover=|onclick=|onfocus=|onsubmit=|onchange=)",
    "XSS - IFRAME/Object": r"(<iframe|<object|<embed)",
    
    "Directory Traversal - Basic": r"(\.\./\.\./|\.\.\\\.\.\\|\.\./)",
    "Directory Traversal - Encoded": r"(%2e%2e%2f|%2e%2e/|%252e%252e%252f|%2e%2e%5c)",
    "Directory Traversal - Windows": r"(c:\\windows\\win.ini|c:\\boot.ini)",
    
    "Command Injection - Chain": r"(;|&&|\|\||\$\(|`|\|)",
    "Command Injection - Tools": r"(whoami|cat|net user|wget|curl|bexec|system\(|nc -e)",
    
    "RCE - Linux Shell": r"(/bin/sh|/bin/bash|/usr/bin/perl|/usr/bin/python)",
    "RCE - Windows Shell": r"(cmd\.exe|powershell\.exe)",
    
    "LFI - Local File Inclusion": r"(/etc/passwd|/proc/self/environ|/var/log|/etc/shadow)",
    "RFI - Remote File Inclusion": r"(http://|https://|ftp://).+\.(php|txt|conf)",
    "SSRF - Cloud Metadata": r"(http://169\.254\.169\.254|metadata\.google\.internal)",
    
    "Brute Force Indicator": r"\b(failed login|unauthorized|invalid password|authentication failure|login failed)\b",
    "Credential Stuffing Probe": r"(\busername=|\blogin=|\buser=).{1,80}(\bpassword=|\bpass=|\bpwd=)",
    
    "Sensitive File - Config": r"(wp-config\.php|\.env|config\.php|settings\.py|database\.yml)",
    "Sensitive File - Keys": r"(id_rsa|id_dsa|\.pem|\.ppk)",
    "Sensitive File - Git": r"(\.git/HEAD|\.git/config|\.git/index)",
    "Sensitive File - Backup": r"(\.bak|\.old|\.sql|\.dump)",
    
    "Scanner - SQLMap": r"(sqlmap)",
    "Scanner - Nikto/Burp": r"(nikto|burp|acunetix|nessus|nmap)",
    "Scanner - Automation": r"(python-requests|curl|wget|libwww-perl)",
    
    "Web Shell / Backdoor": r"(c99\.php|r57\.php|shell\.php|cmd\.php|eval\(base64_decode)",
    "Log4Shell (CVE-2021-44228)": r"(\$\{jndi:ldap|\$\{jndi:rmi|\$\{jndi:dns)",
    "Shellshock (CVE-2014-6271)": r"(\(\)\s*\{\s*:;\s*\}\s*;)",
    
    "Status 403 Forbidden": r"\b(403)\b",
    "Status 500 Server Error": r"\b(500|502|503|504)\b"
}

# --- 2. CORE FUNCTIONS ---

def normalize_input(text):
    if not text: return ""
    text = urllib.parse.unquote(text)
    text = urllib.parse.unquote(text) # Double decode
    return html.unescape(text)

class ThreatReport(FPDF):
    def header(self):
        self.set_font('Arial', 'B', 15)
        self.cell(0, 10, 'Log-Based Threat Detection Report', 0, 1, 'C')
        self.ln(10)
    def footer(self):
        self.set_y(-15)
        self.set_font('Arial', 'I', 8)
        self.cell(0, 10, f'Page {self.page_no()}', 0, 0, 'C')

# --- 3. GUI APPLICATION ---

class LogThreatApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Log-Based Threat Detection System")
        self.root.geometry("1400x800")
        
        self.threat_rules = DEFAULT_RULES.copy()

        # UI Styling - Dark Theme
        style = ttk.Style()
        style.theme_use('clam')
        style.configure("Treeview", background="#2b2b2b", foreground="white", rowheight=25, fieldbackground="#2b2b2b")
        style.map('Treeview', background=[('selected', '#0078d7')])
        style.configure("TFrame", background="#1e1e1e")
        style.configure("TLabel", background="#1e1e1e", foreground="white")
        style.configure("TButton", font=('Helvetica', 9, 'bold'))

        self.parsed_logs = []
        self.detected_alerts = []
        self.create_widgets()

    def create_widgets(self):
        # Top Panel
        control_frame = ttk.Frame(self.root, padding="10")
        control_frame.pack(side=tk.TOP, fill=tk.X)

        title_label = ttk.Label(control_frame, text="Log-Based Threat Detection", font=("Impact", 18))
        title_label.pack(side=tk.LEFT, padx=10)

        # Buttons
        btns = [
            ("Upload & Parse Log", "#007bff", self.upload_log),
            ("Run Detection", "#28a745", self.run_detection),
            ("Add Rule", "#17a2b8", self.add_rule_dialog),
            ("Remove Rule", "#ffc107", self.remove_rule_dialog),
            ("Show Rules", "#00e5ff", self.show_rules),
            ("Export CSV", "#fd7e14", self.export_csv),
            ("Dashboard", "#d500f9", self.show_dashboard),
            ("PDF Report", "#d63384", self.generate_report)
        ]
        for t, c, cmd in btns:
            fg = "black" if t in ["Remove Rule", "Show Rules"] else "white"
            tk.Button(control_frame, text=t, bg=c, fg=fg, command=cmd).pack(side=tk.LEFT, padx=5)

        # --- KEY FIX: PANED WINDOW FOR EQUAL SPLIT ---
        # This allows resizing and ensures both panels get equal space initially
        self.paned_window = tk.PanedWindow(self.root, orient=tk.HORIZONTAL, sashwidth=5, bg="#333333")
        self.paned_window.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Left Frame (Parsed Logs)
        left_frame = ttk.LabelFrame(self.paned_window, text="Parsed Logs")
        self.paned_window.add(left_frame, minsize=400) # Minimum width to keep headers visible

        columns_log = ("Time", "IP", "Status", "Request")
        self.tree_logs = ttk.Treeview(left_frame, columns=columns_log, show="headings")
        self.tree_logs.heading("Time", text="Time")
        self.tree_logs.heading("IP", text="Source IP")
        self.tree_logs.heading("Status", text="Status")
        self.tree_logs.heading("Request", text="Request")
        
        # Column Widths
        self.tree_logs.column("Time", width=140)
        self.tree_logs.column("IP", width=110)
        self.tree_logs.column("Status", width=60)
        self.tree_logs.column("Request", width=400) # Wider request column

        log_scroll = ttk.Scrollbar(left_frame, orient="vertical", command=self.tree_logs.yview)
        self.tree_logs.configure(yscrollcommand=log_scroll.set)
        log_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.tree_logs.pack(fill=tk.BOTH, expand=True)

        # Right Frame (Alerts Panel)
        right_frame = ttk.LabelFrame(self.paned_window, text="Alerts Panel")
        self.paned_window.add(right_frame, minsize=400) # Equal minimum width

        columns_alert = ("Rule", "Time", "IP", "Snippet")
        self.tree_alerts = ttk.Treeview(right_frame, columns=columns_alert, show="headings")
        self.tree_alerts.heading("Rule", text="Threat Rule")
        self.tree_alerts.heading("Time", text="Time")
        self.tree_alerts.heading("IP", text="Attacker IP")
        self.tree_alerts.heading("Snippet", text="Snippet")
        
        # Alerts Column Widths (Adjusted for visibility)
        self.tree_alerts.column("Rule", width=180)
        self.tree_alerts.column("Time", width=140)
        self.tree_alerts.column("IP", width=110)
        self.tree_alerts.column("Snippet", width=300)

        # RED TEXT TAG
        self.tree_alerts.tag_configure('threat', foreground='#ff3333')

        alert_scroll = ttk.Scrollbar(right_frame, orient="vertical", command=self.tree_alerts.yview)
        self.tree_alerts.configure(yscrollcommand=alert_scroll.set)
        alert_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.tree_alerts.pack(fill=tk.BOTH, expand=True)

        # Status Bar
        self.status_var = tk.StringVar()
        self.status_var.set("Ready. Upload a log file.")
        tk.Label(self.root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W).pack(side=tk.BOTTOM, fill=tk.X)

    # --- FUNCTIONALITY ---
    def upload_log(self):
        f = filedialog.askopenfilename()
        if not f: return
        self.parsed_logs = []
        for i in self.tree_logs.get_children(): self.tree_logs.delete(i)
        
        try:
            with open(f, 'r', errors='ignore') as file:
                for line in file:
                    m = re.search(r'(\d+\.\d+\.\d+\.\d+) - - \[(.*?)\] "(.*?)" (\d+)', line)
                    if m:
                        ip, t, r, s = m.groups()
                        self.parsed_logs.append({"ip": ip, "time": t, "req": r, "status": s})
                        self.tree_logs.insert("", tk.END, values=(t, ip, s, r))
                    else:
                        self.parsed_logs.append({"ip": "?", "time": "?", "req": line.strip(), "status": "?"})
                        self.tree_logs.insert("", tk.END, values=("?", "?", "?", line.strip()[:50]))
            self.status_var.set(f"Loaded {len(self.parsed_logs)} lines.")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def run_detection(self):
        if not self.parsed_logs:
            messagebox.showwarning("Warning", "Upload log first.")
            return

        self.detected_alerts = []
        for i in self.tree_alerts.get_children(): self.tree_alerts.delete(i)

        total_threats = 0
        blocked_ips = set()

        for log in self.parsed_logs:
            ip = log['ip']
            req = normalize_input(log['req'])
            time = log['time']
            
            is_threat = False
            if ip in THREAT_INTEL_IOCS:
                self.add_alert("Threat Intel Match", time, ip, "Known Bad IP")
                is_threat = True
            else:
                for name, pat in self.threat_rules.items():
                    if re.search(pat, req, re.IGNORECASE):
                        self.add_alert(name, time, ip, log['req'][:50])
                        is_threat = True
                        break
            
            if is_threat:
                total_threats += 1
                blocked_ips.add(ip)
                AUTO_BLOCK_LIST.add(ip)

        self.status_var.set(f"Found {total_threats} threats.")
        popup = f"Scan Complete!\nTotal Threats: {total_threats}\nIPs Added to Blocklist: {len(blocked_ips)}"
        messagebox.showinfo("Detection Done", popup)

    def add_alert(self, rule, time, ip, snippet):
        self.detected_alerts.append({"rule": rule, "time": time, "ip": ip, "snippet": snippet})
        self.tree_alerts.insert("", tk.END, values=(rule, time, ip, snippet), tags=('threat',))

    def show_dashboard(self):
        """Enhancement 2: Robust Dashboard with Safe Time Parsing & Demo Mode"""
        
        # --- DEMO DATA GENERATOR ---
        if not self.detected_alerts:
            is_demo = True
            messagebox.showinfo("Demo Mode", "No real threats found yet.\nShowing DASHBOARD with SAMPLE DATA for preview.")
            
            # Fake Data for visualization
            rules = ["SQL Injection", "XSS", "SQL Injection", "Brute Force", "DDoS", "XSS", "Malware", "SQL Injection"]
            ips = ["192.168.1.5", "10.0.0.2", "192.168.1.5", "172.16.0.55", "192.168.1.5", "10.0.0.2"]
            times = ["10:00", "10:05", "10:10", "11:00", "11:15", "11:20", "12:00", "12:30"]
        else:
            is_demo = False
            # Real Data Processing
            rules = [alert['rule'] for alert in self.detected_alerts]
            ips = [alert['ip'] for alert in self.detected_alerts]
            
            # --- FIX FOR ERROR: Safe Time Parsing ---
            times = []
            for alert in self.detected_alerts:
                raw_time = str(alert['time']).strip()
                try:
                    # Case 1: If time has a space (e.g., "2025-12-13 10:00:00")
                    if " " in raw_time:
                        parsed_time = raw_time.split()[1][:5] # Take HH:MM part
                        times.append(parsed_time)
                    # Case 2: If time is just time (e.g., "10:00:00")
                    elif len(raw_time) >= 5:
                        times.append(raw_time[:5])
                    # Case 3: Fallback
                    else:
                        times.append("00:00")
                except Exception:
                    times.append("00:00")

        # --- COUNTS ---
        time_counts = Counter(times)
        sorted_times = sorted(time_counts.items())
        rule_counts = Counter(rules)
        ip_counts = Counter(ips).most_common(5)

        # --- PROFESSIONAL STYLING (Teal & Dark Theme) ---
        bg_color = '#263238'   
        text_color = '#ffffff' 
        colors_list = ['#e63946', '#457b9d', '#a8dadc', '#f1faee', '#1d3557'] 
        
        # Use a safe backend or standard plt
        try:
            plt.style.use('dark_background')
        except:
            pass 

        fig = plt.figure(figsize=(13, 7), facecolor=bg_color)
        title_text = 'Threat Detection Dashboard (DEMO MODE)' if is_demo else 'Threat Detection Dashboard'
        fig.suptitle(title_text, fontsize=16, color=text_color, fontweight='bold', y=0.96)

        gs = fig.add_gridspec(2, 2, height_ratios=[1, 0.8])

        # --- 1. DONUT CHART ---
        ax1 = fig.add_subplot(gs[0, 0])
        ax1.set_facecolor(bg_color)
        
        if rule_counts:
            wedges, texts, autotexts = ax1.pie(
                rule_counts.values(), 
                labels=rule_counts.keys(), 
                autopct='%1.1f%%', 
                startangle=140, 
                colors=colors_list,
                pctdistance=0.80,
                wedgeprops=dict(width=0.4, edgecolor=bg_color)
            )
            plt.setp(texts, color=text_color, fontsize=8)
            plt.setp(autotexts, size=8, weight="bold", color="white")
        
        ax1.set_title("Threat Distribution", color='#a8dadc', fontsize=11)

        # --- 2. BAR CHART ---
        ax2 = fig.add_subplot(gs[0, 1])
        ax2.set_facecolor(bg_color)
        
        if ip_counts:
            ips_x, counts_y = zip(*ip_counts)
            y_pos = range(len(ips_x))
            ax2.barh(y_pos, counts_y, color='#e63946', height=0.5) 
            ax2.set_yticks(y_pos)
            ax2.set_yticklabels(ips_x, color='white', fontsize=9)
            ax2.invert_yaxis()
            
            ax2.spines['top'].set_visible(False)
            ax2.spines['right'].set_visible(False)
            ax2.spines['bottom'].set_color('#546e7a')
            ax2.spines['left'].set_visible(False)
            
            for i, v in enumerate(counts_y):
                ax2.text(v + 0.1, i + 0.1, str(v), color='white', fontsize=9)
                
            ax2.set_title("Top Attacker IPs", color='#e63946', fontsize=11)

        # --- 3. TIMELINE ---
        ax3 = fig.add_subplot(gs[1, :])
        ax3.set_facecolor(bg_color)
        
        if sorted_times:
            t_labels, t_values = zip(*sorted_times)
            ax3.plot(t_labels, t_values, color='#457b9d', linewidth=2, marker='o', markersize=4)
            ax3.fill_between(t_labels, t_values, color='#457b9d', alpha=0.2)
            
            ax3.set_title("Attack Timeline", color='#457b9d', fontsize=11)
            ax3.tick_params(axis='x', rotation=45, colors='white', labelsize=8)
            ax3.tick_params(axis='y', colors='white')
            
            ax3.grid(color='#546e7a', linestyle='--', linewidth=0.5, alpha=0.3)
            ax3.spines['top'].set_visible(False)
            ax3.spines['right'].set_visible(False)
            ax3.spines['bottom'].set_color('#546e7a')
            ax3.spines['left'].set_color('#546e7a')

        plt.tight_layout(pad=2.0)
        plt.show()
    def show_rules(self):
        win = tk.Toplevel(self.root)
        win.title("Configured Threat Rules")
        win.geometry("900x600")
        win.configure(bg="#121212")
        txt = scrolledtext.ScrolledText(win, bg="#1e1e1e", fg="#a0a0a0", font=("Consolas", 11))
        txt.pack(fill=tk.BOTH, expand=True)
        txt.tag_config('blue', foreground='#00e5ff', font=("Consolas", 11, "bold"))
        for name, pat in self.threat_rules.items():
            txt.insert(tk.END, f"Rule: {name}\n", 'blue')
            txt.insert(tk.END, f"Regex: {pat}\n\n")
        txt.config(state='disabled')

    def add_rule_dialog(self):
        n = simpledialog.askstring("New Rule", "Name:")
        p = simpledialog.askstring("New Rule", "Regex:")
        if n and p: self.threat_rules[n] = p

    def remove_rule_dialog(self):
        if not self.threat_rules: return
        win = tk.Toplevel(self.root)
        lb = tk.Listbox(win)
        lb.pack(fill=tk.BOTH, expand=True)
        for r in self.threat_rules: lb.insert(tk.END, r)
        def rem():
            if lb.curselection():
                del self.threat_rules[lb.get(lb.curselection())]
                win.destroy()
        tk.Button(win, text="Remove", command=rem).pack()

    def export_csv(self):
        if not self.detected_alerts: return
        f = filedialog.asksaveasfilename(defaultextension=".csv")
        if f:
            with open(f, 'w', newline='') as csvfile:
                w = csv.writer(csvfile)
                w.writerow(["Rule", "Time", "IP", "Snippet"])
                for a in self.detected_alerts: w.writerow([a['rule'], a['time'], a['ip'], a['snippet']])
            messagebox.showinfo("Success", "CSV Saved.")

    def generate_report(self):
        if not self.detected_alerts: return
        pdf = ThreatReport()
        pdf.add_page()
        pdf.set_font("Arial", size=10)
        pdf.cell(0, 10, f"Total Threats: {len(self.detected_alerts)}", ln=True)
        pdf.ln(5)
        pdf.cell(60, 10, "Rule", 1)
        pdf.cell(40, 10, "IP", 1)
        pdf.cell(50, 10, "Time", 1)
        pdf.ln()
        for a in self.detected_alerts:
            pdf.cell(60, 10, a['rule'][:25], 1)
            pdf.cell(40, 10, a['ip'], 1)
            pdf.cell(50, 10, a['time'][:20], 1)
            pdf.ln()
        pdf.output("Report.pdf")
        messagebox.showinfo("Success", "PDF Generated.")

if __name__ == "__main__":
    root = tk.Tk()
    app = LogThreatApp(root)
    root.mainloop()