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
                # Add fragment, data length, source port, badsum for evasion
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

# --- Passive Packet Sniffer ---

def packet_sniffer(interface="eth0", count=100, timeout=15):
    if not scapy_installed:
        return {"error": "Scapy is not installed. Run `pip install scapy`."}
    try:
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

# --- Fast FTP Brute-Force (can expand to SSH/SMB/HTTP) ---

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
            time.sleep(rate_limit)  # Rate limit
    return results

# --- Lightweight Vuln/Misconfig Checks ---

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
        # Simple check via nmap's ssl-enum-ciphers
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
        if st.button("Run Nmap Scan") and target:
            with st.spinner("Running scan..."):
                result = st.session_state.bot.run_nmap_scan(target, scan_type, timing, evasion)
                st.session_state.last_scan = result

    tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs([
        "💬 Chat Assistant", "🔍 Scan Results", "📶 Packet Sniffer", 
        "🛡️ Vuln Checks", "🔑 Brute-Force", "📝 YARA Rules"
    ])

    # --- Tab 2: Scan Results ---
    with tab2:
        st.header("Scan Results")
        if 'last_scan' in st.session_state:
            result = st.session_state.last_scan
            if 'error' in result:
                st.error(f"Scan Error: {result['error']}")
            else:
                st.markdown(f"**Scan Command:** `{result.get('command', 'N/A')}`")
                output = result.get('stdout', '')
                scan_type = result.get("scan_type", "")
                st.markdown(f"⏰ <b>Scan finished at:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", unsafe_allow_html=True)
                if scan_type == "basic":
                    if "Host is up" in output:
                        st.success("🎯 Host is **up and reachable!**")
                    elif "Host seems down" in output:
                        st.error("❌ Host is **down or unreachable.**")
                    else:
                        st.info(output)
                else:
                    port_table, details = parse_ports(output)
                    if port_table:
                        render_port_tags(port_table)
                        st.markdown("#### Port Table")
                        st.markdown(render_port_table(port_table), unsafe_allow_html=True)
                        # Expandable details
                        for port, state, service, info in port_table:
                            if details.get(port):
                                with st.expander(f"📝 Details for {port} ({service})", expanded=False):
                                    st.code("\n".join(details[port]), language="text")
                    else:
                        st.warning("No open ports detected.")
                    # Gemini AI summary
                    if st.button("AI Insight (Pro)"):
                        st.markdown("⌛ Gemini analyzing results...")
                        ai = st.session_state.bot.get_ai_response(
                            "Explain these nmap scan results in plain English for a non-technical user. Which ports are most interesting and why?",
                            output
                        )
                        st.markdown(ai)
                # Raw output expander
                st.markdown("---")
                with st.expander("Raw Nmap Output"):
                    st.code(output, language="text")
        else:
            st.info("No scan results yet. Run a scan from the sidebar.")

    # --- Tab 1: AI Chat ---
    with tab1:
        st.header("AI Security Assistant")
        if 'messages' not in st.session_state:
            st.session_state.messages = []
        for message in st.session_state.messages:
            with st.chat_message(message["role"]):
                st.markdown(message["content"])
        if prompt := st.chat_input("Ask about cybersecurity, tools, or techniques..."):
            st.session_state.messages.append({"role": "user", "content": prompt})
            with st.chat_message("user"):
                st.markdown(prompt)
            with st.chat_message("assistant"):
                with st.spinner("Thinking..."):
                    context = ""
                    if 'last_scan' in st.session_state:
                        context = f"Recent scan results: {json.dumps(st.session_state.last_scan, indent=2)}"
                    response = st.session_state.bot.get_ai_response(prompt, context)
                    st.markdown(response)
                    st.session_state.messages.append({"role": "assistant", "content": response})

    # --- Tab 3: Passive Packet Sniffer ---
    with tab3:
        st.header("Passive Packet Monitor")
        if not scapy_installed:
            st.error("Scapy is not installed. Run `pip install scapy`.")
        else:
            iface = st.text_input("Network Interface", value="eth0")
            count = st.number_input("Packet Count", value=50, min_value=1, max_value=10000)
            timeout_val = st.number_input("Timeout (seconds)", value=15, min_value=1, max_value=600)
            if st.button("Start Sniffing"):
                with st.spinner("Sniffing packets..."):
                    sniffed = packet_sniffer(interface=iface, count=int(count), timeout=int(timeout_val))
                if isinstance(sniffed, dict) and "error" in sniffed:
                    st.error(sniffed["error"])
                else:
                    st.success(f"Captured {len(sniffed)} packets.")
                    st.dataframe(sniffed)

    # --- Tab 4: Vuln/Misconfig Checks ---
    with tab4:
        st.header("Vulnerability & Misconfiguration Checks")
        protocol = st.selectbox("Protocol", ["HTTP", "SSL/TLS", "FTP"])
        target_url = st.text_input("Target (IP/Domain or URL)")
        if st.button("Run Check"):
            if protocol == "HTTP":
                results = http_header_check(target_url)
                st.json(results)
            elif protocol == "SSL/TLS":
                results = ssl_cipher_check(target_url)
                if "nmap_ssl_enum_ciphers" in results:
                    st.code(results["nmap_ssl_enum_ciphers"])
                else:
                    st.json(results)
            elif protocol == "FTP":
                results = ftp_anon_check(target_url)
                st.json(results)

    # --- Tab 5: Brute-Force ---
    with tab5:
        st.header("Brute-Force Authentication Testing")
        st.info("Currently supports FTP; more protocols can be added.")
        host = st.text_input("FTP Host/IP")
        usernames = st.text_area("Usernames (one per line)", value="anonymous\nftp\nadmin")
        passwords = st.text_area("Passwords (one per line)", value="anonymous\npassword\n123456\nadmin")
        rate = st.slider("Rate Limit (seconds between attempts)", min_value=0.0, max_value=5.0, value=0.2, step=0.1)
        if st.button("Start FTP Brute-Force") and host:
            user_list = [u.strip() for u in usernames.splitlines() if u.strip()]
            pass_list = [p.strip() for p in passwords.splitlines() if p.strip()]
            with st.spinner("Testing credentials..."):
                results = ftp_bruteforce(host, user_list, pass_list, rate_limit=rate)
            st.write("Results:")
            st.dataframe(results)
            hits = [r for r in results if r['status'] == "Success"]
            if hits:
                st.success(f"Valid credentials found: {hits}")
            else:
                st.warning("No valid credentials found.")

    # --- Tab 6: YARA ---
    with tab6:
        st.header("YARA Rule Builder & File Scanner")
        yara_templates = {
            "Suspicious String": '''rule suspicious_string_rule
{
    meta:
        description = "Detects suspicious string in files"
        author = "CyberSec Assistant"
        date = "%s"
    strings:
        $string1 = "malware"
    condition:
        $string1
}''' % datetime.now().strftime('%Y-%m-%d'),
            "PE File (Windows EXE)": '''rule pe_file_rule
{
    meta:
        description = "Detects PE executable files"
        author = "CyberSec Assistant"
        date = "%s"
    strings:
        $mz = { 4D 5A }
    condition:
        $mz at 0
}''' % datetime.now().strftime('%Y-%m-%d'),
            "Custom (edit below)": ""
        }
        selected_template = st.selectbox("YARA Rule Template", list(yara_templates.keys()))
        rule_content = st.text_area(
            "YARA Rule",
            yara_templates[selected_template] if selected_template != "Custom (edit below)" else "",
            height=300,
            key="rule_editor"
        )
        col1, col2 = st.columns(2)
        with col1:
            if st.button("Validate Rule"):
                result = st.session_state.bot.create_yara_rule(rule_content)
                if result['status'] == 'success':
                    st.success(result['message'])
                else:
                    st.error(result['message'])
            if st.button("Explain Rule with Gemini AI"):
                if st.session_state.bot.genai_client:
                    ai_response = st.session_state.bot.get_ai_response(
                        "Explain this YARA rule and what it is designed to detect:",
                        rule_content
                    )
                    st.markdown(ai_response)
                else:
                    st.warning("Configure Gemini API first.")
        with col2:
            uploaded_files = st.file_uploader(
                "Upload files to scan", type=['exe', 'dll', 'pdf', 'doc', 'txt'],
                accept_multiple_files=True
            )
            if uploaded_files and rule_content:
                if st.button("Scan Files"):
                    matches_found = False
                    for uploaded_file in uploaded_files:
                        with tempfile.NamedTemporaryFile(delete=False) as tmp_file:
                            tmp_file.write(uploaded_file.read())
                            tmp_path = tmp_file.name
                        try:
                            result = st.session_state.bot.scan_with_yara(tmp_path, rule_content)
                            if result['status'] == 'success':
                                if result['matches']:
                                    matches_found = True
                                    st.success(f"Matches in `{uploaded_file.name}`:")
                                    for match in result['matches']:
                                        st.write(f"**Rule:** `{match['rule']}`")
                                        if match['tags']:
                                            st.write(f"**Tags:** {match['tags']}")
                                        if match['meta']:
                                            st.write(f"**Meta:** {match['meta']}")
                                        if match['strings']:
                                            for (offset, identifier, data) in match['strings']:
                                                st.write(
                                                    f"String `{identifier}` matched at offset `{offset}`: `{str(data)[:30]}...`"
                                                )
                                else:
                                    st.info(f"No matches found in `{uploaded_file.name}`.")
                            else:
                                st.error(f"Scan failed for `{uploaded_file.name}`: {result['message']}")
                        finally:
                            os.unlink(tmp_path)
                    if not matches_found:
                        st.warning("No matches found in any files.")

    st.markdown("---")
    st.markdown("""
    <div style="text-align: center; color: #666;">
        <p>🛡️ CyberSec Assistant - For Ethical Security Research Only</p>
        <p>Always ensure proper authorization before testing systems</p>
    </div>
    """, unsafe_allow_html=True)

if __name__ == "__main__":
    main()
