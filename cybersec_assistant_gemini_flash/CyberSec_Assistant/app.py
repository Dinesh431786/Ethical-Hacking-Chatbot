import streamlit as st
import google.generativeai as genai
import subprocess
import json
import re
import os
import tempfile
from datetime import datetime
import yara
import requests
import time

from ftplib import FTP, error_perm
try:
    from scapy.all import sniff, IP, TCP
    scapy_installed = True
except ImportError:
    scapy_installed = False

st.set_page_config(page_title="CyberSec Assistant", page_icon="🛡️", layout="wide")

# --- Port Parsing and Display Functions ---

def parse_ports(output):
    port_table = []
    details = {}
    in_table = False
    lines = output.splitlines()
    current_port = None

    for line in lines:
        # Table header (start)
        if line.strip().startswith("PORT "):
            in_table = True
            continue
        if in_table:
            # End table if not a port line
            if not line.strip() or not re.match(r"^\d+/", line):
                in_table = False
                continue
            parts = re.split(r'\s+', line, maxsplit=3)
            if len(parts) >= 3:
                port, state, service = parts[:3]
                info = parts[3] if len(parts) > 3 else ""
                port_table.append([port, state, service, info])
                details[port] = []
        # Add details (script output, banners) under ports
        port_match = re.match(r"^(\d+/[a-z]+)", line)
        if port_match:
            current_port = port_match.group(1)
        elif current_port and (line.strip().startswith('|') or line.strip().startswith('_')):
            if current_port in details:
                details[current_port].append(line.strip())
    return port_table, details

def render_port_table(port_table):
    if not port_table:
        return "No open ports detected."
    md = "|  | Port | State | Service | Info |\n|:-:|:-----|:------|:--------|:-----|\n"
    for port, state, service, info in port_table:
        color = "🟢" if state == "open" else ("🔴" if state == "closed" else "⚪")
        md += f"| {color} | `{port}` | **{state.capitalize()}** | `{service}` | {info} |\n"
    return md

def render_port_tags(port_table):
    open_ports = [f"{p[0]} ({p[2]})" for p in port_table if p[1] == "open"]
    if open_ports:
        tag_html = " ".join([
            f"<span style='background:#16a34a;color:#fff;border-radius:6px;padding:3px 8px;margin-right:5px;'>{port}</span>"
            for port in open_ports
        ])
        st.markdown(
            f"🟢 <b>{len(open_ports)} open ports:</b> {tag_html}",
            unsafe_allow_html=True
        )

# --- Gemini & YARA Core Class ---

class EthicalHackingBot:
    def __init__(self):
        self.genai_client = None
    def initialize_gemini(self, api_key):
        try:
            genai.configure(api_key=api_key)
            self.genai_client = genai.GenerativeModel('gemini-1.5-flash')
            return True
        except Exception as e:
            st.error(f"Failed to initialize Gemini API: {str(e)}")
            return False
    def run_nmap_scan(self, target, scan_type, timing="T4", evasion=False):
        try:
            if not self.is_valid_target(target):
                return {"error": "Invalid target. Please provide a valid IP or domain."}
            # Defensive fix: ensure types/values
            if not timing or not isinstance(timing, str) or not timing.startswith("T"):
                timing = "T4"
            if evasion not in [True, False]:
                evasion = False
            scan_commands = {
                "basic": [
                    "nmap", "-sn", "-PE", "-PS80,443,21,22", "-PA3389,8080", target
                ],
                "port_scan": [
                    "nmap", "-sS", f"-{timing}", "--top-ports", "1000", "--reason", "--script=banner", target
                ],
                "service_scan": [
                    "nmap", "-sS", f"-{timing}", "-sV", "--top-ports", "1000", "--reason",
                    "--script=default,banner,http-headers,http-server-header,ssl-enum-ciphers,smb-os-discovery,smb-enum-sessions,ftp-anon", target
                ],
            }
            # Evasion options
            if evasion and scan_type in ["port_scan", "service_scan"]:
                scan_commands[scan_type][1:1] = ["-f", "--data-length", "50", "--source-port", "53", "--badsum"]
            if scan_type not in scan_commands:
                return {"error": "Invalid scan type"}
            result = subprocess.run(scan_commands[scan_type], capture_output=True, text=True, timeout=180)
            return {
                "command": " ".join(scan_commands[scan_type]),
                "stdout": result.stdout,
                "stderr": result.stderr,
                "returncode": result.returncode,
                "scan_type": scan_type
            }
        except subprocess.TimeoutExpired:
            return {"error": "Scan timed out after 3 minutes"}
        except Exception as e:
            return {"error": f"Scan failed: {str(e)}"}
    def create_yara_rule(self, rule_content):
        try:
            yara.compile(source=rule_content)
            return {"status": "success", "message": "YARA rule compiled successfully"}
        except yara.SyntaxError as e:
            return {"status": "error", "message": f"YARA syntax error: {str(e)}"}
        except Exception as e:
            return {"status": "error", "message": f"Error: {str(e)}"}
    def scan_with_yara(self, file_path, rule_content):
        try:
            rules = yara.compile(source=rule_content)
            matches = rules.match(file_path, timeout=30)
            return {
                "status": "success",
                "matches": [
                    {
                        "rule": match.rule,
                        "tags": match.tags,
                        "meta": match.meta,
                        "strings": match.strings
                    }
                    for match in matches
                ]
            }
        except Exception as e:
            return {"status": "error", "message": f"Scan failed: {str(e)}"}
    def is_valid_target(self, target):
        ip_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
        return bool(re.match(ip_pattern, target) or re.match(domain_pattern, target))
    def get_ai_response(self, user_input, context=""):
        if not self.genai_client:
            return "Please configure your Gemini API key first."
        try:
            system_prompt = """You are a cybersecurity expert assistant focused on ethical hacking and security research.
You provide guidance on:
- Network reconnaissance and scanning
- Vulnerability assessment
- Malware analysis
- Security best practices
- Tool usage (nmap, YARA, etc.)
Always emphasize ethical use and proper authorization. Never assist with illegal activities.
Provide detailed, technical responses with practical examples when appropriate."""
            full_prompt = f"{system_prompt}\n\nContext: {context}\n\nUser Query: {user_input}"
            response = self.genai_client.generate_content(full_prompt)
            return response.text
        except Exception as e:
            return f"Error getting AI response: {str(e)}"

# --- Passive Packet Sniffer, Brute-Force, Vuln Checks (unchanged) ---
# (Use the same as in previous versions for brevity...)

def packet_sniffer(interface="eth0", count=100, timeout=15):
    if not scapy_installed:
        return {"error": "Scapy is not installed. Run `pip install scapy`."}
    try:
        from scapy.all import sniff, IP, TCP
        packets = sniff(iface=interface, count=count, timeout=timeout)
        result = []
        for pkt in packets:
            if IP in pkt:
                summary = {
                    "src": pkt[IP].src,
                    "dst": pkt[IP].dst,
                    "proto": pkt[IP].proto,
                }
                if TCP in pkt:
                    summary["sport"] = pkt[TCP].sport
                    summary["dport"] = pkt[TCP].dport
                result.append(summary)
        return result
    except Exception as e:
        return {"error": str(e)}

def ftp_bruteforce(host, user_list, pass_list, timeout=3, rate_limit=0.2):
    results = []
    for username in user_list:
        for password in pass_list:
            try:
                ftp = FTP(host, timeout=timeout)
                ftp.login(user=username, passwd=password)
                results.append({"username": username, "password": password, "status": "Success"})
                ftp.quit()
            except error_perm:
                results.append({"username": username, "password": password, "status": "Fail"})
            except Exception as ex:
                results.append({"username": username, "password": password, "status": f"Error: {ex}"})
            time.sleep(rate_limit)
    return results

def http_header_check(url):
    try:
        if not url.startswith("http"):
            url = "http://" + url
        r = requests.get(url, timeout=5)
        info = {
            "Status": r.status_code,
            "Server": r.headers.get("Server"),
            "X-Powered-By": r.headers.get("X-Powered-By"),
            "Missing-Security-Headers": []
        }
        sec_headers = [
            "X-Frame-Options", "Strict-Transport-Security", 
            "Content-Security-Policy", "X-XSS-Protection"
        ]
        for h in sec_headers:
            if h not in r.headers:
                info["Missing-Security-Headers"].append(h)
        return info
    except Exception as e:
        return {"error": str(e)}

def ftp_anon_check(host):
    try:
        ftp = FTP(host, timeout=5)
        ftp.login()
        ftp.quit()
        return {"anonymous_login": True}
    except Exception as e:
        return {"anonymous_login": False, "error": str(e)}

def ssl_cipher_check(host, port=443):
    try:
        cmd = ["nmap", "--script=ssl-enum-ciphers", "-p", str(port), host]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        return {"nmap_ssl_enum_ciphers": result.stdout}
    except Exception as e:
        return {"error": str(e)}

# --- Streamlit UI ---
def main():
    st.markdown("""
    <div class="main-header">
        <h1 style="color: white; margin: 0;">🛡️ CyberSec Assistant</h1>
        <p style="color: #e0e0e0; margin: 0;">Ethical Hacking & Security Research Tool</p>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("""
    <div class="warning-box">
        <h4>⚠️ Ethical Use Only</h4>
        <p>This tool is designed for authorized security testing and research only.
        Ensure you have proper permission before scanning any systems. Unauthorized
        access to computer systems is illegal.</p>
    </div>
    """, unsafe_allow_html=True)

    if 'bot' not in st.session_state:
        st.session_state.bot = EthicalHackingBot()

    # ---- Sidebar: Configuration ----
    with st.sidebar:
        st.header("Configuration")
        gemini_key = st.text_input("Gemini API Key", type="password")
        if gemini_key and not st.session_state.bot.genai_client:
            if st.session_state.bot.initialize_gemini(gemini_key):
                st.success("Gemini API initialized!")
        st.header("Nmap Quick Scan")
        target = st.text_input("Target (IP/Domain)", placeholder="192.168.1.1 or example.com")
        scan_type = st.selectbox("Nmap Scan Type", ["basic", "port_scan", "service_scan"])
        timing = st.selectbox("Timing (T1–T5, higher=faster/less accurate)", ["T3", "T4", "T5"], index=1)
        evasion = st.checkbox("Enable Firewall/IDS Evasion", value=False)
        if st.button("Run Nmap Scan") and target and scan_type and timing is not None:
            # Defensive: print debug output for diagnosis
            st.write(f"DEBUG: target={target}, scan_type={scan_type}, timing={timing}, evasion={evasion}")
            with st.spinner("Running scan..."):
                result = st.session_state.bot.run_nmap_scan(str(target), str(scan_type), str(timing), bool(evasion))
                st.session_state.last_scan = result

    # ... all other tabs remain the same as in the previous version ...

    # (Paste tabs and logic as in previous answer, omitted here for brevity.)

if __name__ == "__main__":
    main()
