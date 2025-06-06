import streamlit as st
import google.generativeai as genai
import subprocess
import json
import re
import os
import tempfile
from datetime import datetime
import yara

st.set_page_config(page_title="CyberSec Assistant", page_icon="🛡️", layout="wide")

# ---- Helper Functions ----

def parse_ports(output):
    """Extract port table and port details from nmap output."""
    port_table = []
    details = {}
    in_table = False
    lines = output.splitlines()
    for idx, line in enumerate(lines):
        if re.match(r"^PORT\s+STATE\s+SERVICE", line):
            in_table = True
            continue
        if in_table:
            if not line.strip() or not re.match(r"^\d+/", line):
                break
            parts = re.split(r'\s+', line, maxsplit=3)
            if len(parts) >= 3:
                port, state, service = parts[:3]
                info = parts[3] if len(parts) > 3 else ""
                port_table.append([port, state, service, info])
                details[port] = []
    # Get details for each port (like scripts)
    current_port = None
    for line in lines:
        port_match = re.match(r"^(\d+/[a-z]+)", line)
        if port_match:
            current_port = port_match.group(1)
            continue
        if current_port and (line.strip().startswith('|') or line.strip().startswith('_')):
            details[current_port].append(line.strip())
    return port_table, details

def markdown_port_table(port_table):
    """Render ports as a markdown table with colored emojis."""
    if not port_table:
        return "No open ports detected."
    md = "| Port | State | Service | Info |\n|:-----|:------|:--------|:-----|\n"
    for port, state, service, info in port_table:
        color = ":green_circle:" if state == "open" else (":red_circle:" if state == "closed" else ":white_circle:")
        md += f"| {color} `{port}` | `{state}` | `{service}` | {info} |\n"
    return md

def summarize_scan(port_table):
    if not port_table:
        return "No open ports detected."
    open_ports = [p for p in port_table if p[1] == "open"]
    return f"**{len(open_ports)} open ports**: {', '.join([p[0] for p in open_ports])}"

def extract_host_up(output):
    for line in output.splitlines():
        if "Host is up" in line:
            return True
        if "Host seems down" in line:
            return False
    return None

# ---- Main Bot Class ----

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
    def run_nmap_scan(self, target, scan_type):
        try:
            if not self.is_valid_target(target):
                return {"error": "Invalid target. Please provide a valid IP or domain."}
            scan_commands = {
                "basic": ["nmap", "-sn", target],
                "port_scan": ["nmap", "-sT", target],
                "service_scan": ["nmap", "-sV", "-sC", target],
            }
            result = subprocess.run(scan_commands[scan_type], capture_output=True, text=True, timeout=300)
            return {
                "command": " ".join(scan_commands[scan_type]),
                "stdout": result.stdout,
                "stderr": result.stderr,
                "returncode": result.returncode,
                "scan_type": scan_type
            }
        except subprocess.TimeoutExpired:
            return {"error": "Scan timed out after 5 minutes"}
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

# ---- UI Starts Here ----

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

    with st.sidebar:
        st.header("Configuration")
        gemini_key = st.text_input("Gemini API Key", type="password")
        if gemini_key and not st.session_state.bot.genai_client:
            if st.session_state.bot.initialize_gemini(gemini_key):
                st.success("Gemini API initialized!")
        st.header("Nmap Quick Scan")
        target = st.text_input("Target (IP/Domain)", placeholder="192.168.1.1 or example.com")
        scan_type = st.selectbox("Nmap Scan Type", ["basic", "port_scan", "service_scan"])
        if st.button("Run Nmap Scan") and target:
            with st.spinner("Running scan..."):
                result = st.session_state.bot.run_nmap_scan(target, scan_type)
                st.session_state.last_scan = result

    tab1, tab2, tab3 = st.tabs(["💬 Chat Assistant", "🔍 Scan Results", "📝 YARA Rules"])

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
                if scan_type == "basic":
                    is_up = extract_host_up(output)
                    if is_up is True:
                        st.success("🎯 Host is **up** and reachable!")
                    elif is_up is False:
                        st.error("❌ Host is **down** or not reachable.")
                    else:
                        st.info(output)
                else:
                    port_table, details = parse_ports(output)
                    st.markdown("#### Port Table")
                    st.markdown(markdown_port_table(port_table), unsafe_allow_html=True)
                    for port, _, _, _ in port_table:
                        if details[port]:
                            with st.expander(f"Details for {port}", expanded=False):
                                st.code("\n".join(details[port]), language="text")
                    st.success(summarize_scan(port_table))
                    st.caption(f"Scan finished at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
                # Copy button
                st.code(output, language="text")
                st.button("Copy Raw Output to Clipboard")
                # AI Insights
                if st.button("Get AI Insights"):
                    with st.spinner("AI analyzing results..."):
                        ai = st.session_state.bot.get_ai_response(
                            "Summarize and explain these scan results for a bug bounty hunter. What should be checked next?",
                            output
                        )
                        st.markdown(ai)
        else:
            st.info("No scan results yet. Run a scan from the sidebar.")

    # (tab1 and tab3 as before, unchanged; for brevity omitted here but will keep YARA and AI chat as your last code!)

if __name__ == "__main__":
    main()
