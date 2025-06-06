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

# ==== NMAP OUTPUT PARSERS ====

def parse_network_map(output):
    hosts = []
    for line in output.splitlines():
        m = re.search(r'Nmap scan report for ([^\s]+) \(([\d\.]+)\)', line)
        if m:
            host = m.group(1)
            ip = m.group(2)
            hosts.append({"host": host, "ip": ip})
        elif "Host is up" in line and hosts:
            lat = re.search(r'(\d+\.\d+)s latency', line)
            hosts[-1]["latency"] = lat.group(1) + "s" if lat else ""
    return hosts

def parse_ports(output):
    ports = []
    details = {}
    current_port = None
    for line in output.splitlines():
        # Find port lines like: 80/tcp  open  http  Apache httpd 2.4.41 ((Ubuntu))
        m = re.match(r'^(\d+/\w+)\s+(\w+)\s+([^\s]+)\s*(.*)$', line)
        if m:
            port, state, service, extra = m.groups()
            ports.append((port, state, service, extra))
            current_port = port
            details[current_port] = []
        elif current_port and (line.startswith("|") or line.startswith("_")):
            details[current_port].append(line)
        elif current_port and line.strip() == "":
            current_port = None
    return ports, details

# ==== RISK/AI SECTION ====

def get_gemini_risk(genai_client, table, details, target):
    if not genai_client or not table:
        return ""
    try:
        lines = ["Ports and services found:\n"]
        for p in table:
            lines.append(f"- {p[0]} ({p[2]}): {p[3]}")
        lines.append(f"\nDetails: {json.dumps(details)}")
        response = genai_client.generate_content(
            "Act as a cybersecurity analyst. Analyze this nmap scan, summarize security risks, and suggest next steps:\n"
            + "\n".join(lines)
            + f"\nFor {target}"
        )
        return response.text
    except Exception:
        return ""

# ==== BOT LOGIC ====

class EthicalHackingBot:
    def __init__(self):
        self.genai_client = None

    def initialize_gemini(self, api_key):
        try:
            genai.configure(api_key=api_key)
            self.genai_client = genai.GenerativeModel('gemini-1.5-flash')
            return True
        except Exception as e:
            st.error(f"Gemini API error: {str(e)}")
            return False

    def run_nmap(self, target, scan_type):
        # Map scan_type to real nmap command
        commands = {
            "network_map": ["nmap", "-sn", target],
            "port_scan": ["nmap", "-sT", target],
            "service_scan": ["nmap", "-sV", "-sC", target],
        }
        cmd = commands.get(scan_type)
        if not cmd:
            return {"error": "Invalid scan type"}
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
            return {
                "command": " ".join(cmd),
                "stdout": res.stdout,
                "stderr": res.stderr,
                "finished": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
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

# ==== MAIN STREAMLIT APP ====

st.set_page_config(page_title="CyberSec Assistant", page_icon="🛡️", layout="wide")
st.markdown("""<style>
.main-header {background: linear-gradient(90deg, #1e3c72 0%, #2a5298 100%); padding: 1rem; border-radius: 10px; margin-bottom: 2rem;}
.tool-box {background: #f0f2f6; padding: 1rem; border-radius: 8px; margin: 1rem 0;}
.warning-box {background: #fff3cd; border: 1px solid #ffeaa7; padding: 1rem; border-radius: 8px; margin: 1rem 0;}
.success-box {background: #d4edda; border: 1px solid #c3e6cb; padding: 1rem; border-radius: 8px; margin: 1rem 0;}
</style>""", unsafe_allow_html=True)

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
                    # Save history
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

    tab1, tab2, tab3, tab4 = st.tabs([
        "💬 Chat Assistant", "🔍 Scan Results", "📈 Network Map", "📝 YARA Rules"
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
                    response = ""
                    if bot.genai_client:
                        response = bot.genai_client.generate_content(prompt).text
                    else:
                        response = "Configure Gemini API first."
                    st.markdown(response)
                    st.session_state.messages.append({"role": "assistant", "content": response})

    # ==== SCAN RESULTS TAB ====
    with tab2:
        st.header("Scan Results")
        last = st.session_state.get("last_scan")
        if not last or "stdout" not in last:
            st.info("No scan results yet. Run a scan from the sidebar.")
        else:
            st.markdown(f"**Scan Command:** `{last['command']}`")
            st.markdown(f"⏰ <b>Scan finished at:</b> {last['finished']}", unsafe_allow_html=True)
            scan_type = last["command"].split()[1]
            if scan_type == "-sn":
                hosts = parse_network_map(last["stdout"])
                st.markdown("<b>Discovered Hosts:</b>", unsafe_allow_html=True)
                if hosts:
                    table = "<table><tr><th></th><th>Host</th><th>IP</th><th>Latency</th></tr>"
                    for h in hosts:
                        table += f"<tr><td>🟢</td><td>{h['host']}</td><td>{h['ip']}</td><td>{h.get('latency','')}</td></tr>"
                    table += "</table>"
                    st.markdown(table, unsafe_allow_html=True)
                else:
                    st.warning("No live hosts detected.")
            else:
                port_table, details = parse_ports(last["stdout"])
                st.markdown("<h5>Port Table</h5>", unsafe_allow_html=True)
                port_rows = ""
                for port, state, service, info in port_table:
                    color = "🟢" if state.lower() == "open" else "🔴"
                    port_rows += f"<tr><td>{color}</td><td><b>{port}</b></td><td>{state.title()}</td><td>{service}</td><td>{info}</td></tr>"
                st.markdown(
                    f"<table><tr><th></th><th>Port</th><th>State</th><th>Service</th><th>Info</th></tr>{port_rows}</table>",
                    unsafe_allow_html=True,
                )
                # Collapsible details for each port
                for port, data in details.items():
                    if data:
                        with st.expander(f"Show details for {port}"):
                            st.markdown("\n".join(data))
                open_ports = [p[0] for p in port_table if p[1].lower() == "open"]
                st.markdown(f"<b>{len(open_ports)} open ports:</b> {', '.join(open_ports)}", unsafe_allow_html=True)
                # Gemini Risk Analysis
                if bot.genai_client:
                    if st.button("AI: Summarize Security Risk", key="risk"):
                        with st.spinner("Gemini analyzing..."):
                            ai_out = get_gemini_risk(bot.genai_client, port_table, details, target)
                            st.markdown(ai_out)

            st.markdown("<h6>Full Nmap Output</h6>", unsafe_allow_html=True)
            st.code(last["stdout"], language="text")

            # History/Diff
            if "scan_history" in st.session_state and len(st.session_state.scan_history) > 1:
                prev = st.session_state.scan_history[-2]
                prev_ports, _ = parse_ports(prev["result"].get("stdout", ""))
                prev_open = set([p[0] for p in prev_ports if p[1].lower() == "open"])
                now_open = set([p[0] for p in port_table if p[1].lower() == "open"])
                new_ports = now_open - prev_open
                closed_ports = prev_open - now_open
                if new_ports:
                    st.info(f"🆕 <b>New open ports since last scan:</b> {', '.join(new_ports)}", unsafe_allow_html=True)
                if closed_ports:
                    st.warning(f"❌ <b>Ports now closed:</b> {', '.join(closed_ports)}", unsafe_allow_html=True)

    # ==== NETWORK MAP TAB ====
    with tab3:
        st.header("Network Map")
        # Show all network_map scans from history
        nmaps = [x for x in st.session_state.get("scan_history", []) if x["scan_type"] == "network_map"]
        if not nmaps:
            st.info("Run a network map scan to visualize hosts.")
        else:
            hosts = []
            for scan in nmaps:
                hosts.extend(parse_network_map(scan["result"].get("stdout", "")))
            if hosts:
                st.markdown("<b>Discovered Hosts (all scans):</b>", unsafe_allow_html=True)
                table = "<table><tr><th></th><th>Host</th><th>IP</th><th>Latency</th></tr>"
                for h in hosts:
                    table += f"<tr><td>🟢</td><td>{h['host']}</td><td>{h['ip']}</td><td>{h.get('latency','')}</td></tr>"
                table += "</table>"
                st.markdown(table, unsafe_allow_html=True)
            else:
                st.warning("No live hosts detected.")

    # ==== YARA TAB (same as before, can be improved further) ====
    with tab4:
        st.header("YARA Rule Builder & File Scanner")
        sample_rule = f'''rule suspicious_string_rule
{{
    meta:
        description = "Detects suspicious string in files"
        author = "CyberSec Assistant"
        date = "{datetime.now().strftime('%Y-%m-%d')}"
    strings:
        $string1 = "malware"
    condition:
        $string1
}}'''
        rule_content = st.text_area("YARA Rule", sample_rule, height=200)
        col1, col2 = st.columns(2)
        with col1:
            if st.button("Validate Rule"):
                result = bot.create_yara_rule(rule_content)
                if result['status'] == 'success':
                    st.success(result['message'])
                else:
                    st.error(result['message'])
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
                            result = bot.scan_with_yara(tmp_path, rule_content)
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
