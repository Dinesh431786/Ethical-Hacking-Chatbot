import streamlit as st
import nmap
import sqlite3
import socket
import google.generativeai as genai
from datetime import datetime
from scapy.all import IP, TCP, sr1, conf, sr
import whois

conf.verb = 0

# =============== Branding ====================
st.set_page_config(page_title="Voxelta CyberSec Pro Suite", page_icon="🛡️", layout="centered")
st.markdown("""
<div style="background: linear-gradient(90deg,#1e3c72 0%,#2a5298 100%);
padding:1.3rem 2rem; border-radius:12px;margin-bottom:1.1rem;">
  <h2 style="color:#fff;margin-bottom:0;">🛡️ Voxelta CyberSec Pro Suite</h2>
  <div style="color:#ffe057;">ICP: Security Engineers, Researchers & Students | 
    <a style="color:#ffe057;" href="https://www.linkedin.com/in/dinesh-k-3199ab1b0/" target="_blank">Dinesh K</a>
  </div>
</div>
""", unsafe_allow_html=True)

# =============== Gemini Helper ===============
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

# ============= Sidebar: Tool Selector ===============
with st.sidebar:
    st.header("⚙️ Tool & AI Setup")
    gkey = st.text_input("Gemini API Key", type="password")
    if gkey and not st.session_state["gemini_init"]:
        st.session_state["gemini"] = GeminiBot()
        if st.session_state["gemini"].init(gkey):
            st.success("Gemini Connected!")
            st.session_state["gemini_init"] = True

    tool = st.radio("Choose Tool", [
        "Nmap Pro Scanner", 
        "SQL Injection Test", 
        "Reverse DNS & Whois",
        "Scapy SYN/Advanced"
    ], format_func=lambda x: {
        "Nmap Pro Scanner": "🛡️ Nmap Pro",
        "SQL Injection Test": "🩸 SQL Injection",
        "Reverse DNS & Whois": "🔁 DNS/Whois",
        "Scapy SYN/Advanced": "⚡ Scapy Advanced"
    }[x])

st.write("")  # spacing

# =========== NMAP ADVANCED PANEL ============
if tool == "Nmap Pro Scanner":
    st.subheader("🛡️ Nmap Pro: All-Mode Network Scanning")
    scan_modes = {
        "Host Discovery (Ping)": "-sn",
        "TCP Port Scan": "-T4 -F",
        "Service & Version": "-sV",
        "OS Detection": "-O",
        "Aggressive Full": "-A",
        "Vuln Scripts": "--script vuln",
        "Custom": None
    }
    scan = st.selectbox("Scan Type", list(scan_modes.keys()))
    target = st.text_input("Target (IP/domain/subnet)", value="scanme.nmap.org")
    port_range = st.text_input("Port Range/List", value="1-1024 (ignored except Custom)", help="E.g. 1-65535 or 22,80,443")
    timing = st.selectbox("Timing Template", ["-T0 (Paranoid)", "-T1", "-T2", "-T3", "-T4 (Default)", "-T5 (Insane)"], index=3)
    scripts = st.text_input("NSE Scripts", value="", help="E.g. http-enum,ftp-anon (comma-separated, empty for none)")
    custom_args = ""
    if scan == "Custom":
        custom_args = st.text_input("Custom Nmap Args", value="-sS -p 80,443 --script=http-enum", key="main_args")

    if st.button("Run Nmap Scan"):
        if not target:
            st.error("Please enter a target!")
        else:
            args = ""
            if scan == "Custom":
                args = custom_args
            else:
                args = scan_modes[scan]
                if port_range and scan != "Host Discovery (Ping)":
                    pr = port_range.split(" ")[0]  # remove (ignored..) note
                    args += f" -p {pr}"
                args += f" {timing.split()[0]}"
                if scripts.strip():
                    args += f" --script {scripts}"
            st.info(f"Running: nmap {args} {target}")
            nm = nmap.PortScanner()
            try:
                nm.scan(target, arguments=args)
                result = nm.csv()
                st.code(result, language="text")
                st.download_button("⬇️ Download Result (.txt)", result, file_name=f"nmap_{scan}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
                if st.session_state["gemini"] and st.toggle("Gemini AI Analysis", key="nmap_ai"):
                    prompt = f"Explain this Nmap {scan} result for a security expert."
                    st.success(st.session_state["gemini"].analyze(result, prompt=prompt))
            except Exception as e:
                st.error(f"Nmap error: {e}")

# =========== SQL INJECTION PANEL ============
elif tool == "SQL Injection Test":
    st.subheader("🩸 SQL Injection Tester (SQLite3)")
    st.info("Simulate/test SQL Injection on a demo database. Shows why unparameterized queries are dangerous. For education!")
    payload = st.text_input("SQLi Payload", value="' OR 1=1 --")
    def check_sql_injection(payload):
        db = sqlite3.connect(":memory:")
        c = db.cursor()
        c.execute("CREATE TABLE users (id INT, name TEXT);")
        c.execute("INSERT INTO users VALUES (1, 'admin'), (2, 'test');")
        try:
            query = f"SELECT * FROM users WHERE name = '{payload}'"
            c.execute(query)
            return c.fetchall()
        except Exception as e:
            return f"Error: {e}"
    if st.button("Test SQL Injection"):
        res = check_sql_injection(payload)
        st.code(str(res), language="text")
        if st.session_state["gemini"] and st.toggle("Gemini AI Analysis", key="sql_ai"):
            prompt = "Explain this SQL injection result and the security impact."
            st.success(st.session_state["gemini"].analyze(str(res), prompt=prompt))

# =========== REVERSE DNS & WHOIS PANEL ============
elif tool == "Reverse DNS & Whois":
    st.subheader("🔁 Reverse DNS & Whois Lookup")
    ips = st.text_area("IP Addresses (one per line)", value="8.8.8.8\n1.1.1.1")
    domains = st.text_area("Domains for Whois (one per line)", value="google.com\nvoxelta.com")
    def reverse_dns(ip):
        try:
            return socket.gethostbyaddr(ip)[0]
        except Exception as e:
            return f"Reverse DNS failed: {e}"
    if st.button("Run DNS/Whois"):
        ip_list = [x.strip() for x in ips.splitlines() if x.strip()]
        for ip in ip_list:
            st.write(f"**{ip}:** `{reverse_dns(ip)}`")
        doms = [x.strip() for x in domains.splitlines() if x.strip()]
        for d in doms:
            try:
                w = whois.whois(d)
                st.write(f"**{d}:** Name: `{w.name}` | Org: `{w.org}` | Email: `{w.emails}`")
            except Exception as e:
                st.write(f"{d}: Whois failed: {e}")
        if st.session_state["gemini"] and st.toggle("Gemini AI Analysis", key="dns_ai"):
            summary = f"IPs: {ip_list}\nDomains: {doms}"
            prompt = "Explain these DNS and Whois results for OSINT/cyber security."
            st.success(st.session_state["gemini"].analyze(summary, prompt=prompt))

# =========== SCAPY ADVANCED PANEL ============
elif tool == "Scapy SYN/Advanced":
    st.subheader("⚡ Scapy TCP SYN Scan (Multi-Port, Hex Dump, Flags)")
    st.info("Sends SYN packets. Shows open/closed, TCP flags, hex dump. Needs root/admin on some systems.")
    scapy_ip = st.text_input("Target IP", value="8.8.8.8")
    ports = st.text_input("Ports (comma or dash separated)", value="53,80,443")
    show_hexdump = st.checkbox("Show Packet Hexdump", value=True)
    def scapy_tcp_multi_scan(target_ip, ports, show_hex=True):
        try:
            results = []
            if '-' in ports:
                p_start, p_end = [int(x) for x in ports.split('-')]
                portlist = list(range(p_start, p_end+1))
            else:
                portlist = [int(x) for x in ports.split(',')]
            for port in portlist:
                pkt = IP(dst=target_ip)/TCP(dport=port,flags="S")
                resp = sr1(pkt, timeout=2)
                line = f"Port {port}: "
                if resp and resp.haslayer(TCP):
                    flags = resp.sprintf("%TCP.flags%")
                    if resp[TCP].flags == 0x12:
                        line += "Open (SYN/ACK)"
                    elif resp[TCP].flags == 0x14:
                        line += "Closed (RST)"
                    else:
                        line += f"Flag: {flags}"
                    if show_hex:
                        hexstr = str(bytes(resp).hex())
                        line += f" | Hex: {hexstr[:40]}..."
                else:
                    line += "No response or filtered"
                results.append(line)
            return "\n".join(results)
        except Exception as e:
            return f"Scapy error: {e}"
    if st.button("Run Scapy Scan"):
        scanres = scapy_tcp_multi_scan(scapy_ip, ports, show_hexdump)
        st.code(scanres, language="text")
        if st.session_state["gemini"] and st.toggle("Gemini AI Analysis", key="scapy_ai"):
            prompt = "Explain these Scapy TCP SYN scan results, with port status and packet analysis."
            st.success(st.session_state["gemini"].analyze(str(scanres), prompt=prompt))

# =============== FOOTER ==================
st.markdown("""
    <hr style="margin-top:2.2em;margin-bottom:0;">
    <div style='text-align: center; color: #666; font-size: 1em;'>
        Made with ❤️ by <b>Voxelta Private Limited</b>.<br>
        <a href='https://www.linkedin.com/in/dinesh-k-3199ab1b0/' target='_blank'>Dinesh K on LinkedIn</a>
    </div>
""", unsafe_allow_html=True)
