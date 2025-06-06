import streamlit as st
import google.generativeai as genai
import subprocess
import json
import re
import os
import tempfile
from datetime import datetime
import yara
import socket

# --------- Parsing Helpers ---------
def parse_ports(nmap_output):
    port_table = []
    details = {}
    lines = nmap_output.splitlines()
    capture = False
    for line in lines:
        if re.match(r"PORT\s+STATE\s+SERVICE", line):
            capture = True
            continue
        if capture:
            if not line.strip() or line.startswith("Nmap done"):
                break
            fields = re.split(r"\s+", line, maxsplit=3)
            if len(fields) >= 3:
                port, state, service = fields[:3]
                info = fields[3] if len(fields) == 4 else ""
                port_table.append([port, state, service, info])
                details[port] = []
        elif port_table and (line.startswith("|") or line.startswith("_") or line.startswith("SF-")):
            last_port = port_table[-1][0]
            details[last_port].append(line.strip())
    return port_table, details

def parse_network_map(nmap_output):
    hosts = []
    host = {}
    for line in nmap_output.splitlines():
        if "Nmap scan report for" in line:
            if host:
                hosts.append(host)
                host = {}
            m = re.match(r"Nmap scan report for (.*) \(([\d\.]+)\)", line)
            if m:
                host["host"] = m.group(1)
                host["ip"] = m.group(2)
            else:
                m2 = re.match(r"Nmap scan report for ([\d\.]+)", line)
                if m2:
                    host["host"] = host["ip"] = m2.group(1)
        if "latency" in line:
            host["latency"] = line.strip()
    if host:
        hosts.append(host)
    return hosts

def get_gemini_risk(genai_client, port_table, details, target):
    port_lines = "\n".join([f"{p[0]}: {p[1]}, {p[2]}, {p[3]}" for p in port_table])
    prompt = f"""
You are a professional cybersecurity assistant.
Given this network scan for {target}, summarize the likely security risks, explain what each open port/service might mean, and note any best practices.

Scan results:
{port_lines}
Details:
{json.dumps(details, indent=2)}
"""
    try:
        response = genai_client.generate_content(prompt)
        return response.text
    except Exception as e:
        return f"Gemini API error: {str(e)}"

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

    def run_nmap(self, target, scan_type="port_scan"):
        scan_map = {
            "network_map": ["nmap", "-sn", target],
            "port_scan": ["nmap", "-sT", target],
            "service_scan": ["nmap", "-sV", "-sC", target],
        }
        cmd = scan_map.get(scan_type, scan_map["port_scan"])
        try:
            start = datetime.utcnow()
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            finish = datetime.utcnow()
            return {
                "command": " ".join(cmd),
                "stdout": result.stdout,
                "stderr": result.stderr,
                "returncode": result.returncode,
                "finished": finish.strftime("%Y-%m-%d %H:%M:%S"),
            }
        except subprocess.TimeoutExpired:
            return {"error": "Scan timed out after 2 minutes"}
        except Exception as e:
            return {"error": f"Scan failed: {str(e)}"}

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
        <p>This tool is designed for authorized security testing and research only. Ensure you have proper permission before scanning any systems. Unauthorized access to computer systems is illegal.</p>
    </div>
    """, unsafe_allow_html=True)

    if 'bot' not in st.session_state:
        st.session_state.bot = EthicalHackingBot()
    bot = st.session_state.bot

    # ---- SIDEBAR CONFIG ----
    with st.sidebar:
        st.header("Configuration")
        gemini_key = st.text_input("Gemini API Key", type="password")
        if gemini_key and not bot.genai_client:
            if bot.initialize_gemini(gemini_key):
                st.success("Gemini API initialized!")

        st.header("Nmap Quick Scan")
        target = st.text_input("Target (IP/Domain)", "google.com")
        scan_type = st.selectbox("Nmap Scan Type", [
            "network_map", "port_scan", "service_scan"
        ], format_func=lambda x: {
            "network_map": "Network Map (Ping Discovery)",
            "port_scan": "Port Scan (TCP)",
            "service_scan": "Service/Version Scan"
        }[x])

        if st.button("Run Scan") and target:
            with st.spinner("Running nmap scan..."):
                result = bot.run_nmap(target, scan_type)
                if "stdout" in result:
                    if "scan_history" not in st.session_state:
                        st.session_state.scan_history = []
                    st.session_state.scan_history.append({
                        "scan_type": scan_type,
                        "target": target,
                        "result": result
                    })
                    st.session_state.last_scan = result
                else:
                    st.session_state.last_scan = result

    tab1, tab2, tab3 = st.tabs([
        "💬 Chat Assistant", "🔍 Scan Results", "📈 Network Map"
    ])

    # ==== CHAT TAB ====
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
                    if 'last_scan' in st.session_state and st.session_state.last_scan.get("stdout"):
                        context = f"Recent scan results: {st.session_state.last_scan['stdout'][:1000]}"
                    response = bot.get_ai_response(prompt, context)
                    st.markdown(response)
                    st.session_state.messages.append({"role": "assistant", "content": response})

    # ==== SCAN RESULTS TAB ====
    with tab2:
        st.header("Scan Results")
        last = st.session_state.get("last_scan")
        if not last or "stdout" not in last:
            st.info("No scan results yet. Run a scan from the sidebar.")
        elif "error" in last:
            st.error(last["error"])
        else:
            st.markdown(f"**Scan Command:** `{last['command']}`")
            st.markdown(f"⏰ <b>Scan finished at:</b> {last['finished']}", unsafe_allow_html=True)
            scan_type_code = last["command"].split()[1]
            # Defensive: Only define these if a port scan/service scan
            port_table, details = [], {}
            if scan_type_code == "-sn":
                hosts = parse_network_map(last["stdout"])
                st.markdown("<b>Discovered Hosts:</b>", unsafe_allow_html=True)
                if hosts:
                    table = "<table><tr><th></th><th>Host</th><th>IP</th><th>Latency</th></tr>"
                    for h in hosts:
                        table += f"<tr><td>🟢</td><td>{h.get('host','')}</td><td>{h.get('ip','')}</td><td>{h.get('latency','')}</td></tr>"
                    table += "</table>"
                    st.markdown(table, unsafe_allow_html=True)
                else:
                    st.warning("No live hosts detected.")
            else:
                port_table, details = parse_ports(last["stdout"])
                if not port_table:
                    st.warning("No open ports detected.")
                else:
                    st.markdown("<h5>Port Table</h5>", unsafe_allow_html=True)
                    port_rows = ""
                    for port, state, service, info in port_table:
                        color = "🟢" if state.lower() == "open" else "🔴"
                        port_rows += f"<tr><td>{color}</td><td><b>{port}</b></td><td>{state.title()}</td><td>{service}</td><td>{info}</td></tr>"
                    st.markdown(
                        f"<table><tr><th></th><th>Port</th><th>State</th><th>Service</th><th>Info</th></tr>{port_rows}</table>",
                        unsafe_allow_html=True,
                    )
                    for port, data in details.items():
                        if data:
                            with st.expander(f"Show details for {port}"):
                                st.markdown("\n".join(data))
                    open_ports = [p[0] for p in port_table if p[1].lower() == "open"]
                    st.markdown(f"<b>{len(open_ports)} open ports:</b> {', '.join(open_ports)}", unsafe_allow_html=True)
                    # Gemini Risk Analysis (safe: only if ports exist)
                    if bot.genai_client and port_table:
                        if st.button("AI: Summarize Security Risk", key="risk"):
                            with st.spinner("Gemini analyzing..."):
                                ai_out = get_gemini_risk(bot.genai_client, port_table, details, target)
                                st.markdown(ai_out)

                    # Port diffing: only if current/previous scans BOTH found ports
                    if (
                        "scan_history" in st.session_state and
                        len(st.session_state.scan_history) > 1 and
                        scan_type_code in ("-sT", "-sV") and port_table
                    ):
                        prev = st.session_state.scan_history[-2]
                        prev_code = prev["result"]["command"].split()[1]
                        prev_ports, _ = parse_ports(prev["result"].get("stdout", "")) if prev_code in ("-sT", "-sV") else ([], {})
                        prev_open = set([p[0] for p in prev_ports if p[1].lower() == "open"])
                        now_open = set([p[0] for p in port_table if p[1].lower() == "open"])
                        new_ports = now_open - prev_open
                        closed_ports = prev_open - now_open
                        if new_ports:
                            st.info(f"🆕 <b>New open ports since last scan:</b> {', '.join(new_ports)}", unsafe_allow_html=True)
                        if closed_ports:
                            st.warning(f"❌ <b>Ports now closed:</b> {', '.join(closed_ports)}", unsafe_allow_html=True)

            st.markdown("<h6>Full Nmap Output</h6>", unsafe_allow_html=True)
            st.code(last["stdout"], language="text")

    # ==== NETWORK MAP TAB ====
    with tab3:
        st.header("Network Mapping (Discovery)")
        last = st.session_state.get("last_scan")
        if not last or "stdout" not in last or last["command"].split()[1] != "-sn":
            st.info("Run a Network Map scan (`-sn`) to see discovered hosts.")
        else:
            hosts = parse_network_map(last["stdout"])
            if hosts:
                st.markdown("### Hosts found:")
                for host in hosts:
                    st.write(host)
            else:
                st.warning("No live hosts detected.")

    st.markdown("""
    <div style="text-align: center; color: #666;">
        <p>🛡️ CyberSec Assistant - For Ethical Security Research Only</p>
        <p>Always ensure proper authorization before testing systems</p>
    </div>
    """, unsafe_allow_html=True)

if __name__ == "__main__":
    main()
