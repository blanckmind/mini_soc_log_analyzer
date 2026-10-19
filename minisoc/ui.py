import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from datetime import datetime
from .database import initialize_database, seed_demo_data, connect_db
from .detection import run_detection
from .csv_tools import import_log_csv, export_alerts_csv

BG = "#101827"
PANEL = "#182437"
NAV_BG = "#111827"
NAV_ACTIVE = "#26364d"
ACCENT = "#38bdf8"
TEXT = "#e5edf7"
MUTED = "#9caec4"
BORDER = "#334155"
CRITICAL = "#dc2626"
HIGH = "#ea580c"
MEDIUM = "#eab308"
LOW = "#16a34a"


class MiniSOC:
    def __init__(self, root):
        self.root = root
        self.root.title("Mini SOC | Security Log Analyzer")
        self.root.geometry("1280x800")
        self.root.minsize(980, 650)
        self.root.configure(bg=BG)

        self.search_var = tk.StringVar()
        self.severity_var = tk.StringVar(value="All")
        self.status_var = tk.StringVar(value="All")
        self.nav_buttons = {}

        self.setup_style()
        self.build_navigation()
        self.build_header()
        self.build_summary_cards()
        self.build_filters()
        self.build_content()
        self.build_footer()
        self.refresh_all()

    def setup_style(self):
        style = ttk.Style()
        style.theme_use("clam")
        style.configure(
            "Treeview", background=PANEL, foreground=TEXT,
            fieldbackground=PANEL, rowheight=32, borderwidth=0,
            font=("Arial", 10)
        )
        style.configure(
            "Treeview.Heading", background=NAV_ACTIVE,
            foreground="#ffffff", relief="flat", padding=9,
            font=("Arial", 10, "bold")
        )
        style.map(
            "Treeview", background=[("selected", "#075985")],
            foreground=[("selected", "#ffffff")]
        )
        style.configure("TNotebook", background=BG, borderwidth=0)
        style.configure(
            "TNotebook.Tab", padding=(16, 9), background=NAV_BG,
            foreground=TEXT, font=("Arial", 10, "bold")
        )
        style.map(
            "TNotebook.Tab", background=[("selected", NAV_ACTIVE)],
            foreground=[("selected", ACCENT)]
        )
        style.configure(
            "Vertical.TScrollbar", background=NAV_ACTIVE,
            troughcolor=BG, bordercolor=BG, arrowcolor=TEXT
        )

    def button(self, parent, text, command, primary=False):
        return tk.Button(
            parent, text=text, command=command,
            bg=ACCENT if primary else NAV_ACTIVE,
            fg="#0f172a" if primary else TEXT,
            activebackground="#0284c7", activeforeground="#ffffff",
            relief="flat", bd=0, padx=12, pady=8,
            cursor="hand2", font=("Arial", 9, "bold")
        )

    def build_navigation(self):
        nav = tk.Frame(self.root, bg=NAV_BG, height=56)
        nav.pack(fill="x")
        nav.pack_propagate(False)
        tk.Label(
            nav, text="◉  MINI SOC", bg=NAV_BG, fg=TEXT,
            font=("Arial", 17, "bold"), padx=22
        ).pack(side="left", fill="y")

        for page in ("Dashboard", "Logs & Events", "Threats", "Reports", "Settings"):
            btn = tk.Button(
                nav, text=page,
                command=lambda name=page: self.navigate(name),
                bg=NAV_ACTIVE if page == "Dashboard" else NAV_BG,
                fg=ACCENT if page == "Dashboard" else TEXT,
                activebackground=NAV_ACTIVE, activeforeground=ACCENT,
                relief="flat", bd=0, padx=15,
                font=("Arial", 10, "bold"), cursor="hand2"
            )
            btn.pack(side="left", fill="y")
            self.nav_buttons[page] = btn

    def navigate(self, page):
        for name, button in self.nav_buttons.items():
            active = name == page
            button.configure(
                bg=NAV_ACTIVE if active else NAV_BG,
                fg=ACCENT if active else TEXT
            )
        if page == "Settings":
            messagebox.showinfo(
                "Settings",
                "Local SQLite storage is enabled.\n\n"
                "Detection rules and thresholds are documented in "
                "minisoc/detection.py."
            )
        elif page == "Reports":
            self.export_alerts()
        elif page == "Threats":
            self.tabs.select(self.alerts_tab)
        elif page == "Logs & Events":
            self.tabs.select(self.events_tab)
        else:
            self.tabs.select(self.overview_tab)

    def build_header(self):
        frame = tk.Frame(self.root, bg=BG)
        frame.pack(fill="x", padx=20, pady=(15, 8))
        left = tk.Frame(frame, bg=BG)
        left.pack(side="left", fill="x", expand=True)
        tk.Label(
            left, text="Security Operations Center", bg=BG, fg=TEXT,
            font=("Arial", 20, "bold")
        ).pack(anchor="w")
        tk.Label(
            left, text="Security monitoring  •  Log analysis  •  Incident response",
            bg=BG, fg=MUTED, font=("Arial", 10)
        ).pack(anchor="w", pady=(3, 0))
        right = tk.Frame(frame, bg=BG)
        right.pack(side="right")
        self.button(right, "Import CSV", self.import_csv).pack(side="left", padx=4)
        self.button(right, "Run Detection", self.detect, True).pack(side="left", padx=4)

    def build_summary_cards(self):
        frame = tk.Frame(self.root, bg=BG)
        frame.pack(fill="x", padx=20, pady=8)
        self.card_values = {}
        for title, key, color, symbol in [
            ("Critical Alerts", "critical", CRITICAL, "▲"),
            ("High Alerts", "high", HIGH, "⚠"),
            ("Medium Alerts", "medium", MEDIUM, "⚑"),
            ("Low Alerts", "low", LOW, "✓"),
        ]:
            card = tk.Frame(frame, bg=color, padx=14, pady=12)
            card.pack(side="left", fill="both", expand=True, padx=(0, 10))
            tk.Label(
                card, text=symbol, bg=color, fg="white",
                font=("Arial", 22, "bold")
            ).pack(side="left", padx=(0, 12))
            inner = tk.Frame(card, bg=color)
            inner.pack(side="left", fill="both", expand=True)
            tk.Label(
                inner, text=title, bg=color, fg="white",
                font=("Arial", 10, "bold")
            ).pack(anchor="w")
            value = tk.Label(
                inner, text="0", bg=color, fg="white",
                font=("Arial", 24, "bold")
            )
            value.pack(anchor="w")
            self.card_values[key] = value

    def build_filters(self):
        bar = tk.Frame(self.root, bg=BG)
        bar.pack(fill="x", padx=20, pady=(8, 5))
        tk.Label(bar, text="Search", bg=BG, fg=TEXT).pack(side="left")
        entry = tk.Entry(
            bar, textvariable=self.search_var, bg=PANEL, fg=TEXT,
            insertbackground=TEXT, relief="flat", width=24
        )
        entry.pack(side="left", padx=8, ipady=7)
        entry.bind("<Return>", lambda event: self.refresh_all())
        self.button(bar, "Search", self.refresh_all).pack(side="left", padx=3)
        self.button(bar, "Clear", self.clear_filters).pack(side="left", padx=3)

        tk.Label(bar, text="Severity", bg=BG, fg=TEXT).pack(side="left", padx=(14, 5))
        severity = ttk.Combobox(
            bar, textvariable=self.severity_var,
            values=["All", "CRITICAL", "HIGH", "MEDIUM", "LOW"],
            state="readonly", width=11
        )
        severity.pack(side="left")
        severity.bind("<<ComboboxSelected>>", lambda event: self.refresh_all())

        tk.Label(bar, text="Status", bg=BG, fg=TEXT).pack(side="left", padx=(12, 5))
        status = ttk.Combobox(
            bar, textvariable=self.status_var,
            values=["All", "Open", "Investigating", "Resolved"],
            state="readonly", width=14
        )
        status.pack(side="left")
        status.bind("<<ComboboxSelected>>", lambda event: self.refresh_all())
        self.button(bar, "Export", self.export_alerts).pack(side="right", padx=3)

    def create_tree(self, parent, columns):
        outer = tk.Frame(parent, bg=BG)
        outer.pack(fill="both", expand=True, padx=8, pady=8)
        tree = ttk.Treeview(
            outer, columns=[c[0] for c in columns], show="headings"
        )
        for name, heading, width in columns:
            tree.heading(name, text=heading)
            tree.column(name, width=width, minwidth=65, anchor="w")
        ybar = ttk.Scrollbar(outer, orient="vertical", command=tree.yview)
        xbar = ttk.Scrollbar(outer, orient="horizontal", command=tree.xview)
        tree.configure(yscrollcommand=ybar.set, xscrollcommand=xbar.set)
        tree.grid(row=0, column=0, sticky="nsew")
        ybar.grid(row=0, column=1, sticky="ns")
        xbar.grid(row=1, column=0, sticky="ew")
        outer.rowconfigure(0, weight=1)
        outer.columnconfigure(0, weight=1)
        return tree

    def build_content(self):
        self.tabs = ttk.Notebook(self.root)
        self.tabs.pack(fill="both", expand=True, padx=20, pady=(7, 10))
        self.events_tab = tk.Frame(self.tabs, bg=BG)
        self.alerts_tab = tk.Frame(self.tabs, bg=BG)
        self.overview_tab = tk.Frame(self.tabs, bg=BG)
        self.tabs.add(self.events_tab, text="Logs & Events")
        self.tabs.add(self.alerts_tab, text="Alerts & Incidents")
        self.tabs.add(self.overview_tab, text="Offenses & Timeline")

        self.events_tree = self.create_tree(self.events_tab, [
            ("id", "ID", 55), ("timestamp", "Event Time", 165),
            ("ip", "Source IP", 135), ("username", "Account", 115),
            ("type", "Event Type", 120), ("status", "Result", 100),
            ("details", "Event Details", 300)
        ])
        self.alerts_tree = self.create_tree(self.alerts_tab, [
            ("id", "ID", 55), ("timestamp", "Timestamp", 155),
            ("ip", "Source IP", 130), ("severity", "Severity", 100),
            ("rule", "Alert Type", 190), ("description", "Description", 300),
            ("status", "Status", 120)
        ])

        self.alerts_tree.tag_configure("CRITICAL", background="#7f1d1d", foreground="#ffffff")
        self.alerts_tree.tag_configure("HIGH", background="#7c2d12", foreground="#ffffff")
        self.alerts_tree.tag_configure("MEDIUM", background="#713f12", foreground="#ffffff")
        self.alerts_tree.tag_configure("LOW", background="#14532d", foreground="#ffffff")

        actions = tk.Frame(self.alerts_tab, bg=BG)
        actions.pack(fill="x", padx=8, pady=(0, 8))
        self.button(actions, "View Details", self.show_alert_details).pack(side="left", padx=3)
        self.button(actions, "Mark Investigating",
                    lambda: self.update_alert_status("Investigating")).pack(side="left", padx=3)
        self.button(actions, "Resolve Alert",
                    lambda: self.update_alert_status("Resolved")).pack(side="left", padx=3)
        self.button(actions, "Reopen Alert",
                    lambda: self.update_alert_status("Open")).pack(side="left", padx=3)

        outer = tk.Frame(self.overview_tab, bg=BG)
        outer.pack(fill="both", expand=True, padx=14, pady=14)
        tk.Label(
            outer, text="Top Offenses", bg=BG, fg=TEXT,
            font=("Arial", 14, "bold")
        ).pack(anchor="w", pady=(0, 8))
        self.offenses_text = tk.Text(
            outer, height=8, bg=PANEL, fg=TEXT, relief="flat",
            font=("Menlo", 11), wrap="word"
        )
        self.offenses_text.pack(fill="x", pady=(0, 15))
        self.offenses_text.configure(state="disabled")
        tk.Label(
            outer, text="Alert Severity Breakdown", bg=BG, fg=TEXT,
            font=("Arial", 14, "bold")
        ).pack(anchor="w", pady=(0, 8))
        self.breakdown_frame = tk.Frame(outer, bg=BG)
        self.breakdown_frame.pack(fill="x", anchor="w")

    def build_footer(self):
        footer = tk.Frame(self.root, bg=NAV_BG)
        footer.pack(fill="x", side="bottom")
        self.footer_label = tk.Label(
            footer, text="Local demo mode | SQLite storage",
            bg=NAV_BG, fg=MUTED, font=("Arial", 9), padx=20, pady=8
        )
        self.footer_label.pack(side="left")
        self.clock_label = tk.Label(
            footer, text="", bg=NAV_BG, fg=MUTED,
            font=("Arial", 9), padx=20
        )
        self.clock_label.pack(side="right")
        self.update_clock()

    def update_clock(self):
        self.clock_label.configure(text=datetime.now().strftime("%d %b %Y | %H:%M:%S"))
        self.root.after(1000, self.update_clock)

    def import_csv(self):
        filepath = filedialog.askopenfilename(
            title="Import security logs",
            filetypes=[("CSV files", "*.csv")]
        )
        if not filepath:
            return
        try:
            inserted, duplicates = import_log_csv(filepath)
            self.refresh_all()
            messagebox.showinfo(
                "Import Complete",
                f"New records imported: {inserted}\nDuplicate records skipped: {duplicates}"
            )
        except (OSError, ValueError, csv.Error) as error:
            messagebox.showerror("Import Failed", str(error))

    def detect(self):
        try:
            count = run_detection()
            self.refresh_all()
            messagebox.showinfo(
                "Analysis Complete",
                f"Detection finished.\nNew alerts created: {count}\n\n"
                "Alerts are rule-based findings, not proof of compromise."
            )
        except Exception as error:
            messagebox.showerror("Detection Error", str(error))

    def export_alerts(self):
        filepath = filedialog.asksaveasfilename(
            title="Export alerts", defaultextension=".csv",
            initialfile="soc_alerts.csv",
            filetypes=[("CSV files", "*.csv")]
        )
        if not filepath:
            return
        try:
            count = export_alerts_csv(filepath)
            messagebox.showinfo("Export Complete", f"Exported {count} alerts.")
        except OSError as error:
            messagebox.showerror("Export Failed", str(error))

    def update_alert_status(self, status):
        selected = self.alerts_tree.selection()
        if not selected:
            messagebox.showwarning("Select Alert", "Select an alert row first.")
            return
        alert_id = self.alerts_tree.item(selected[0], "values")[0]
        with connect_db() as conn:
            conn.execute("UPDATE alerts SET status = ? WHERE id = ?", (status, alert_id))
        self.refresh_all()

    def show_alert_details(self):
        selected = self.alerts_tree.selection()
        if not selected:
            messagebox.showwarning("Select Alert", "Select an alert row first.")
            return
        alert_id = self.alerts_tree.item(selected[0], "values")[0]
        with connect_db() as conn:
            alert = conn.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
        if alert:
            messagebox.showinfo(
                f"Alert #{alert['id']}",
                f"Timestamp: {alert['created_at']}\n"
                f"Source IP: {alert['source_ip']}\n"
                f"Severity: {alert['severity']}\n"
                f"Rule: {alert['rule_name']}\n"
                f"Description: {alert['description']}\n\n"
                f"Evidence:\n{alert['evidence']}\n\n"
                f"Status: {alert['status']}"
            )

    def clear_filters(self):
        self.search_var.set("")
        self.severity_var.set("All")
        self.status_var.set("All")
        self.refresh_all()

    def refresh_all(self):
        query = self.search_var.get().strip().lower()
        with connect_db() as conn:
            total = conn.execute("SELECT COUNT(*) FROM logs").fetchone()[0]
            failed = conn.execute(
                "SELECT COUNT(*) FROM logs WHERE UPPER(status) = 'FAILED'"
            ).fetchone()[0]
            open_alerts = conn.execute(
                "SELECT COUNT(*) FROM alerts WHERE status != 'Resolved'"
            ).fetchone()[0]

            for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                count = conn.execute(
                    "SELECT COUNT(*) FROM alerts WHERE severity = ?", (severity,)
                ).fetchone()[0]
                self.card_values[severity.lower()].configure(text=str(count))

            self.footer_label.configure(
                text=f"Local demo mode  |  {total} events  |  "
                     f"{failed} failed logins  |  {open_alerts} open alerts"
            )

            for item in self.events_tree.get_children():
                self.events_tree.delete(item)
            events = conn.execute("SELECT * FROM logs ORDER BY id DESC").fetchall()
            for row in events:
                values = (
                    row["id"], row["timestamp"], row["source_ip"],
                    row["username"], row["event_type"], row["status"], row["details"]
                )
                if query and not any(query in str(value).lower() for value in values):
                    continue
                self.events_tree.insert("", "end", values=values)

            for item in self.alerts_tree.get_children():
                self.alerts_tree.delete(item)
            alerts = conn.execute("SELECT * FROM alerts ORDER BY id DESC").fetchall()
            for row in alerts:
                values = (
                    row["id"], row["created_at"], row["source_ip"],
                    row["severity"], row["rule_name"], row["description"], row["status"]
                )
                if query and not any(query in str(value).lower() for value in values):
                    continue
                if self.severity_var.get() != "All" and row["severity"] != self.severity_var.get():
                    continue
                if self.status_var.get() != "All" and row["status"] != self.status_var.get():
                    continue
                self.alerts_tree.insert(
                    "", "end", values=values, tags=(row["severity"],)
                )
            self.update_overview(conn)

    def update_overview(self, conn):
        offense_rows = conn.execute("""
            SELECT rule_name, COUNT(*) AS amount
            FROM alerts GROUP BY rule_name ORDER BY amount DESC
        """).fetchall()

        self.offenses_text.configure(state="normal")
        self.offenses_text.delete("1.0", "end")
        if offense_rows:
            for row in offense_rows:
                self.offenses_text.insert(
                    "end", f"• {row['rule_name']}: {row['amount']} alert(s)\n"
                )
        else:
            self.offenses_text.insert("end", "No alerts yet. Run detection to analyze logs.\n")
        self.offenses_text.configure(state="disabled")

        for widget in self.breakdown_frame.winfo_children():
            widget.destroy()

        palette = {"CRITICAL": CRITICAL, "HIGH": HIGH, "MEDIUM": MEDIUM, "LOW": LOW}
        counts = {
            row["severity"]: row["amount"]
            for row in conn.execute(
                "SELECT severity, COUNT(*) AS amount FROM alerts GROUP BY severity"
            ).fetchall()
        }
        maximum = max(counts.values(), default=1)

        for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            amount = counts.get(severity, 0)
            line = tk.Frame(self.breakdown_frame, bg=BG)
            line.pack(fill="x", pady=5)
            tk.Label(
                line, text=severity, width=9, anchor="w",
                bg=BG, fg=TEXT, font=("Menlo", 10, "bold")
            ).pack(side="left")
            bar_bg = tk.Frame(line, bg=PANEL, height=22)
            bar_bg.pack(side="left", fill="x", expand=True, padx=8)
            bar_bg.pack_propagate(False)
            width = int(300 * amount / maximum) if amount else 0
            tk.Frame(bar_bg, bg=palette[severity], height=22, width=width).place(
                x=0, y=0, relheight=1
            )
            tk.Label(
                line, text=str(amount), bg=BG, fg=TEXT, width=4, anchor="e"
            ).pack(side="right")


def launch():
    initialize_database()
    seed_demo_data()
    root = tk.Tk()
    MiniSOC(root)
    root.mainloop()
