import streamlit as st
import nmap
import sqlite3
import socket
import google.generativeai as genai
from datetime import datetime
from scapy.all import IP, TCP, sr1, conf

conf.verb = 0  # suppress scapy output

# ================= Branding & Setup ====================
st.set_page_config(page_title="Voxelta Security Toolkit", page_icon="🛡️", layout="centered")
st.markdown("""
<div style="background: linear-gradient(90deg,#1e3c72 0%,#2a5298 100%);
padding:1.2rem 2rem 1.1rem 2rem; border-radius:13px; margin-bottom:1.2rem;">
  <h2 style="color:#fff;margin-bottom:0;">🛡️ Voxelta Security Toolkit</h2>
  <div style="color:#ffe057;">For Ethical Hackers, Researchers & Students | 
    <a style="color:#ffe057;" href="https://www.linkedin.com/in/dinesh-k-3199ab1b0/" target="_blank">Dinesh K</a>
  </div>
</div>
""", unsafe_allow_html=True)

# ============= Gemini Helper =============
class GeminiBot:
    def __init__(self):
        self.client = None
    def init(self, key):
        try:
            genai.configure(api_key=key)
            self.client = genai.GenerativeModel('gemini-1.5-flash')
            return True
        except Exception as e:
            st.error(f"Gemini error: {e}")
            return False
    def analyze(self, text, prompt=None):
        if not self.client: return ""
        try:
            return self.client.generate_content((prompt or "") + "\n\n" + text).text
        except Exception as e:
            return f"AI Error: {e}"

if "gemini" not in st.session_state: st.session_state["gemini"] = None
if "gemini_init" not in st.session_state: st.session_state["gemini_init"] = False

# ============ Sidebar: Tool Selector & Gemini ===========
with st.sidebar:
    st.header("⚙️ Tool & AI Setup")
    gkey = st.text_input("Gemini API Key", type="password")
    if gkey and not st.session_state["gemini_init"]:
        st.session_state["gemini"] = GeminiBot()
        if st.session_state["gemini"].init(gkey):
            st.success("Gemini Connected!")
            st.session_state["gemini_init"] = True

    tool = st.radio("Choose Tool", [
        "Nmap Scanner", 
        "SQL Injection (SQLite3 Demo)", 
        "Reverse DNS Lookup", 
        "Scapy TCP SYN Scan"
    ], format_func=lambda x: {
        "Nmap Scanner": "🛡️ Nmap Scanner",
        "SQL Injection (SQLite3 Demo)": "🩸 SQL Injection (SQLite3 Demo)",
        "Reverse DNS Lookup": "🔁 Reverse DNS",
        "Scapy TCP SYN Scan": "⚡ Scapy SYN Scan"
    }[x])

st.write("")  # spacing

# ===================== Main Panels ======================

# ----------- 1. NMAP SCANNER PANEL -----------
if tool == "Nmap Scanner":
    st.subheader("🛡️ Advanced Nmap Scanner (python-nmap)")
    scan_modes = {
        "Host Discovery": "-sn",
        "Fast Port Scan": "-T4 -F",
        "Service Detection": "-sV",
        "OS Detection": "-O",
        "Aggressive": "-A",
        "Vuln Scripts": "--script vuln",
        "Custom": None
    }
    scan = st.selectbox("Scan Type", list(scan_modes.keys()))
    target = st.text_input("Target (IP/domain/subnet)", value="scanme.nmap.org")
    custom_args = ""
    if scan == "Custom":
        custom_args = st.text_input("Custom Nmap Args", value="-sS -p 80,443", key="main_args")

    if st.button("Run Nmap Scan"):
        if not target:
            st.error("Please enter a target!")
        else:
            args = custom_args if scan == "Custom" else scan_modes[scan]
            st.info(f"Running: nmap {args} {target}")
            nm = nmap.PortScanner()
            try:
                nm.scan(target, arguments=args)
                result = nm.csv()
                st.code(result, language="text")
                if st.session_state["gemini"] and st.toggle("Gemini AI Analysis", key="main_ai"):
                    prompt = f"Explain this Nmap {scan} scan result as a cyber security expert."
                    st.success(st.session_state["gemini"].analyze(result, prompt=prompt))
                st.download_button("⬇️ Download Result (.txt)", result, file_name=f"nmap_{scan}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
            except Exception as e:
                st.error(f"Nmap error: {e}")

# ----------- 2. SQL INJECTION DEMO PANEL -----------
elif tool == "SQL Injection (SQLite3 Demo)":
    st.subheader("🩸 SQLite3 SQL Injection Demo (Education Only)")
    st.info("Demonstrates how a basic SQL Injection can work if queries are unparameterized. **Never do this in production!**")
    payload = st.text_input("Payload", value="' OR 1=1 --")
    def check_sql_injection(payload):
        db = sqlite3.connect(":memory:")
        c = db.cursor()
        c.execute("CREATE TABLE users (id INT, name TEXT);")
        c.execute("INSERT INTO users VALUES (1, 'admin'), (2, 'test');")
        try:
            # UNSAFE: Demo only!
            query = f"SELECT * FROM users WHERE name = '{payload}'"
            c.execute(query)
            return c.fetchall()
        except Exception as e:
            return f"Error: {e}"
    if st.button("Test SQL Injection"):
        res = check_sql_injection(payload)
        st.code(str(res), language="text")
        if st.session_state["gemini"] and st.toggle("Gemini AI Analysis", key="sql_ai"):
            prompt = "Explain this SQL injection result, and why this is a vulnerability."
            st.success(st.session_state["gemini"].analyze(str(res), prompt=prompt))

# ----------- 3. REVERSE DNS PANEL -----------
elif tool == "Reverse DNS Lookup":
    st.subheader("🔁 Reverse DNS Lookup")
    ip = st.text_input("IP Address", value="8.8.8.8")
    def reverse_dns(ip):
        try:
            return socket.gethostbyaddr(ip)[0]
        except Exception as e:
            return f"Reverse DNS failed: {e}"
    if st.button("Lookup Hostname"):
        result = reverse_dns(ip)
        st.code(result, language="text")
        if st.session_state["gemini"] and st.toggle("Gemini AI Analysis", key="rdns_ai"):
            prompt = "Explain this reverse DNS result for security and OSINT."
            st.success(st.session_state["gemini"].analyze(str(result), prompt=prompt))

# ----------- 4. SCAPY TCP SYN SCAN PANEL -----------
elif tool == "Scapy TCP SYN Scan":
    st.subheader("⚡ Scapy TCP SYN Scan (Single Port)")
    st.info("Sends a raw SYN packet to the target. Needs root/admin on some systems. Best run on Linux.")
    scapy_ip = st.text_input("Target IP", value="8.8.8.8")
    scapy_port = st.number_input("Port", value=53, min_value=1, max_value=65535)
    def scapy_tcp_syn_scan(target_ip, port):
        pkt = IP(dst=target_ip)/TCP(dport=port,flags="S")
        resp = sr1(pkt, timeout=2)
        if resp and resp.haslayer(TCP) and resp[TCP].flags == 0x12:  # SYN/ACK
            return "Port Open"
        return "Port Closed/Filtered"
    if st.button("SYN Scan"):
        try:
            result = scapy_tcp_syn_scan(scapy_ip, int(scapy_port))
            st.code(result, language="text")
            if st.session_state["gemini"] and st.toggle("Gemini AI Analysis", key="scapy_ai"):
                prompt = "Explain this TCP SYN scan result for security research."
                st.success(st.session_state["gemini"].analyze(str(result), prompt=prompt))
        except Exception as e:
            st.error(f"Scapy error: {e}")

# =================== FOOTER ===================
st.markdown("""
    <hr style="margin-top:2.3em;margin-bottom:0;">
    <div style='text-align: center; color: #666; font-size: 1em;'>
        Made with ❤️ by <b>Voxelta Private Limited</b>.<br>
        <a href='https://www.linkedin.com/in/dinesh-k-3199ab1b0/' target='_blank'>Dinesh K on LinkedIn</a>
    </div>
""", unsafe_allow_html=True)
