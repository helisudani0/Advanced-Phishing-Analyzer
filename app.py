import os
import ttkbootstrap as tb
from ttkbootstrap.constants import *
from tkinter import filedialog, messagebox, ttk
from analyzer import analyze_email
from reporting import export_pdf, export_csv_json

PDF_DIR = "reports"
os.makedirs(PDF_DIR, exist_ok=True)

class SOCAnalyzerGUI:
    def __init__(self, master):
        self.master = master
        master.title("SOC-Grade Phishing Analyzer")
        master.geometry("1100x650")

        # Optional: safely load icon if exists
        icon_path = "icon.ico"
        if os.path.exists(icon_path):
            master.iconbitmap(icon_path)

        # Top Frame - Upload & Export
        top_frame = tb.Frame(master)
        top_frame.pack(side=TOP, fill=X, padx=10, pady=5)

        self.upload_btn = tb.Button(top_frame, text="Upload Email (.eml)", bootstyle=INFO, command=self.upload_email)
        self.upload_btn.pack(side=LEFT, padx=5)

        self.export_btn = tb.Button(top_frame, text="Export Reports", bootstyle=SUCCESS, command=self.export_report)
        self.export_btn.pack(side=LEFT, padx=5)

        # Tabs
        self.tabControl = tb.Notebook(master)
        self.tab_overview = tb.Frame(self.tabControl)
        self.tab_headers = tb.Frame(self.tabControl)
        self.tab_urls = tb.Frame(self.tabControl)
        self.tab_attachments = tb.Frame(self.tabControl)
        self.tab_indicators = tb.Frame(self.tabControl)

        self.tabControl.add(self.tab_overview, text='Overview')
        self.tabControl.add(self.tab_headers, text='Headers')
        self.tabControl.add(self.tab_urls, text='URLs')
        self.tabControl.add(self.tab_attachments, text='Attachments')
        self.tabControl.add(self.tab_indicators, text='Indicators')
        self.tabControl.pack(expand=1, fill=BOTH, padx=10, pady=10)

        # Read-only text boxes
        self.overview_text = tb.Text(self.tab_overview, wrap="word", state="disabled", bg="#1e1e1e", fg="#ffffff", insertbackground="#00ff00")
        self.overview_text.pack(expand=1, fill=BOTH, padx=5, pady=5)

        self.indicators_text = tb.Text(self.tab_indicators, wrap="word", state="disabled", bg="#1e1e1e", fg="#ffffff", insertbackground="#00ff00")
        self.indicators_text.pack(expand=1, fill=BOTH, padx=5, pady=5)

        # Treeviews
        self.headers_tree = ttk.Treeview(self.tab_headers, columns=("Value",), show="headings")
        self.headers_tree.heading("Value", text="Value")
        self.headers_tree.pack(expand=1, fill=BOTH, padx=5, pady=5)

        self.urls_tree = ttk.Treeview(self.tab_urls, columns=("Risk", "Explanation"), show="headings")
        self.urls_tree.heading("Risk", text="Risk")
        self.urls_tree.heading("Explanation", text="Explanation")
        self.urls_tree.pack(expand=1, fill=BOTH, padx=5, pady=5)

        self.attachments_tree = ttk.Treeview(self.tab_attachments, columns=("File", "Risk", "Explanation"), show="headings")
        self.attachments_tree.heading("File", text="File")
        self.attachments_tree.heading("Risk", text="Risk")
        self.attachments_tree.heading("Explanation", text="Explanation")
        self.attachments_tree.pack(expand=1, fill=BOTH, padx=5, pady=5)

        self.current_analysis = None

    def upload_email(self):
        file_path = filedialog.askopenfilename(filetypes=[("Email Files", "*.eml")])
        if not file_path:
            return
        try:
            self.current_analysis = analyze_email(file_path)
            self.populate_tabs()
            messagebox.showinfo("Analysis Complete",
                                f"Score: {self.current_analysis['score']}/100\nLevel: {self.current_analysis['level']}")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def populate_tabs(self):
        a = self.current_analysis
        if not a:
            return

        # Overview
        self.overview_text.configure(state="normal")
        self.overview_text.delete(1.0, "end")
        self.overview_text.insert("end",
            f"File: {a['file']}\n"
            f"Timestamp: {a['timestamp']}\n"
            f"Score: {a['score']}/100\n"
            f"Level: {a['level']}\n"
            f"Threat: {a['threat']}\n\n"
            f"TOTAL SCORE BREAKDOWN:\n"
            f"- Header Analysis     : {a.get('header_score',0)}/25\n"
            f"- Content Analysis    : {a.get('content_score',0)}/30\n"
            f"- URL Analysis        : {a.get('url_score',0)}/25\n"
            f"- Attachment Analysis : {a.get('attachment_score',0)}/20\n\n"
            f"Explanation:\n"
        )
        explanation = a.get("explanation", "No issues detected")
        if isinstance(explanation, str):
            self.overview_text.insert("end", explanation + "\n")
        elif isinstance(explanation, dict):
            for sec, txt in explanation.items():
                self.overview_text.insert("end", f"{sec}: {txt}\n")
        else:
            self.overview_text.insert("end", "No issues detected.\n")
        self.overview_text.configure(state="disabled")

        # Headers
        for i in self.headers_tree.get_children(): self.headers_tree.delete(i)
        for k, v in a.get('headers', {}).items():
            self.headers_tree.insert("", "end", values=(f"{k}: {v}",))

        # URLs
        for i in self.urls_tree.get_children(): self.urls_tree.delete(i)
        for u in a.get('urls', []):
            self.urls_tree.insert("", "end", values=(u.get('risk',0), u.get('explanation',"No issues detected")))

        # Attachments
        for i in self.attachments_tree.get_children(): self.attachments_tree.delete(i)
        if a.get('attachments'):
            for att in a['attachments']:
                filename = att.get("filename", "Unknown")
                risk = att.get("risk", 0)
                explanation = att.get("explanation", "No issues detected") if risk == 0 else att.get("explanation")
                self.attachments_tree.insert("", "end", values=(filename, risk, explanation))
        else:
            self.attachments_tree.insert("", "end", values=("No attachments", 0, "No issues detected"))

        # Indicators
        self.indicators_text.configure(state="normal")
        self.indicators_text.delete(1.0, "end")
        self.indicators_text.insert("end",
            f"From: {a.get('from','N/A')}\n"
            f"Return-Path: {a.get('return_path','N/A')}\n"
            f"Content Preview:\n{a.get('content_summary','No content')}\n"
        )
        self.indicators_text.configure(state="disabled")

    def export_report(self):
        if not self.current_analysis:
            messagebox.showwarning("No Data", "Analyze an email first.")
            return

        base_name = os.path.basename(self.current_analysis['file']).replace(".eml", "")
        pdf_path = os.path.join(PDF_DIR, f"{base_name}_analysis.pdf")
        base_path = os.path.join(PDF_DIR, f"{base_name}_analysis")  # CSV + JSON

        # Export PDF + CSV + JSON
        export_pdf(self.current_analysis, pdf_path)
        csv_file, json_file = export_csv_json(self.current_analysis, base_path)

        messagebox.showinfo("Reports Exported",
                            f"PDF: {pdf_path}\nCSV: {csv_file}\nJSON: {json_file}")


if __name__ == "__main__":
    root = tb.Window(themename="darkly")  # SOC industrial dark theme
    gui = SOCAnalyzerGUI(root)
    root.mainloop()