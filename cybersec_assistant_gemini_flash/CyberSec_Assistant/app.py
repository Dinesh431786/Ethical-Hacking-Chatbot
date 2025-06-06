import streamlit as st
import google.generativeai as genai
import subprocess
import json
import re
import os
import tempfile
from datetime import datetime
import yara
import pandas as pd

st.set_page_config(
    page_title="CyberSec Assistant",
    page_icon="🛡️",
    layout="wide"
)

st.markdown("""
<style>
    .main-header {
        background: linear-gradient(90deg, #1e3c72 0%, #2a5298 100%);
        padding: 1rem;
        border-radius: 10px;
        margin-bottom: 2rem;
    }
    .tool-box {
        background: #f0f2f6;
        padding: 1rem;
        border-radius: 8px;
        margin: 1rem 0;
    }
    .warning-box {
        background: #fff3cd;
        border: 1px solid #ffeaa7;
        padding: 1rem;
        border-radius: 8px;
        margin: 1rem 0;
    }
    .success-box {
        background: #d4edda;
        border: 1px solid #c3e6cb;
        padding: 1rem;
        border-radius: 8px;
        margin: 1rem 0;
    }
</style>
""", unsafe_allow_html=True)

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

    def run_nmap_scan(self, target, scan_type="network_map"):
        # Compose nmap command
        scan_commands = {
            "network_map": ["nmap", "-sn", target],
            "port_scan": ["nmap", "-sT", target],  # Fast port scan, no root needed
            "service_scan": ["nmap", "-sV", "-sC", target],  # More detail, a bit slower
        }
        if scan_type not in scan_commands:
            return {"error": "Invalid scan type"}

        command = scan_commands[scan_type]
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=120
            )
            return {
                "command": " ".join(command),
                "stdout": result.stdout,
                "stderr": result.stderr,
                "returncode": result.returncode,
                "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
        except subprocess.TimeoutExpired:
            return {"error": "Scan timed out after 2 minutes"}
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

def parse_ports(nmap_output):
    """
    Returns a tuple: (port_table, details)
    port_table: list of [port, state, service, info]
    details: dict of port to extra nmap lines (script results, etc.)
    """
    lines = nmap_output.splitlines()
    port_section = False
    port_table = []
    details = {}
    current_port = None
    for line in lines:
        # Find port section start
        if re.match(r"PORT\s+STATE\s+SERVICE", line):
            port_section = True
            continue
        if port_section and line.strip() == "":
            break
        if port_section:
            m = re.match(r"(\d+\/\w+)\s+(\w+)\s+(\S+)(.*)", line)
            if m:
                port, state, service, info = m.groups()
                info = info.strip()
                port_table.append([port, state.capitalize(), service, info])
                current_port = port
                details[current_port] = []
            elif current_port and line.startswith("|"):
                details[current_port].append(line.strip())
            elif current_port and line.startswith(" "):
                details[current_port].append(line.strip())
    return port_table, details

def parse_hosts(nmap_output):
    # For -sn output: return all "Nmap scan report for ..." lines
    hosts = []
    for line in nmap_output.splitlines():
        m = re.match(r"Nmap scan report for (.+)", line)
        if m:
            hosts.append(m.group(1))
    return hosts

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

    # --- Sidebar ---
    if 'bot' not in st.session_state:
        st.session_state.bot = EthicalHackingBot()
    bot = st.session_state.bot

    with st.sidebar:
        st.header("Configuration")
        gemini_key = st.text_input("Gemini API Key", type="password")
        if gemini_key and not bot.genai_client:
            if bot.initialize_gemini(gemini_key):
                st.success("Gemini API initialized!")
        st.header("Nmap Quick Scan")
        target = st.text_input("Target (IP/Domain)", placeholder="e.g. google.com")
        scan_type = st.selectbox("Nmap Scan Type", [
            "network_map", "port_scan", "service_scan"
        ], format_func=lambda x: {
            "network_map": "Network Map (Ping Discovery)",
            "port_scan": "Port Scan (Fast)",
            "service_scan": "Service Scan (Advanced)"
        }.get(x, x))
        scan_start = st.button("Run Scan")
        if scan_start and target:
            with st.spinner("Running Nmap scan..."):
                result = bot.run_nmap_scan(target, scan_type)
                st.session_state['last_scan'] = result
                st.session_state['last_scan_type'] = scan_type

    tab1, tab2, tab3 = st.tabs(["💬 Chat Assistant", "🔍 Scan Results", "📝 YARA Rules"])

    # --- Tab 1: Chat ---
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
                        context = f"Recent scan results: {json.dumps(st.session_state['last_scan'], indent=2)}"
                    response = bot.get_ai_response(prompt, context)
                    st.markdown(response)
                    st.session_state.messages.append({"role": "assistant", "content": response})

    # --- Tab 2: Scan Results ---
    with tab2:
        st.header("Scan Results")
        result = st.session_state.get("last_scan", None)
        scan_type = st.session_state.get("last_scan_type", None)
        output = result.get("stdout", "") if result else ""
        port_table, details = parse_ports(output) if output else ([], {})
        st.markdown(f"**Scan Command:** `{result['command']}`" if result else "")
        st.markdown(f"⏰ <b>Scan finished at:</b> {result.get('timestamp', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))}", unsafe_allow_html=True) if result else None

        if result and scan_type == "network_map":
            hosts_up = parse_hosts(output)
            if hosts_up:
                st.markdown("**Discovered Hosts (Online):**")
                for host in hosts_up:
                    st.success(f"🟢 {host}")
            else:
                st.warning("No online hosts found.")
            st.markdown("<br><b>Full Nmap Output</b>", unsafe_allow_html=True)
            st.code(output, language="text")

        elif result and port_table:
            st.markdown("**Port Table**")
            df = pd.DataFrame(port_table, columns=["Port", "State", "Service", "Info"])
            # Show port details with colored status
            def format_port_row(row):
                color = "🟢" if row["State"].lower() == "open" else "🔴"
                return f"{color} {row['Port']}", row["State"], row["Service"], row["Info"]
            formatted_table = [format_port_row(row) for _, row in df.iterrows()]
            st.table(pd.DataFrame(formatted_table, columns=["Port", "State", "Service", "Info"]))
            # Optionally show detailed info
            for port, lines in details.items():
                if lines:
                    with st.expander(f"Advanced Info: {port}"):
                        for l in lines:
                            st.markdown(f"<code>{l}</code>", unsafe_allow_html=True)
            st.markdown("<br><b>Full Nmap Output</b>", unsafe_allow_html=True)
            st.code(output, language="text")
        elif result:
            st.warning("No open ports detected.")
            st.markdown("<br><b>Full Nmap Output</b>", unsafe_allow_html=True)
            st.code(output, language="text")
        else:
            st.info("No scan results yet. Run a scan from the sidebar.")

    # --- Tab 3: YARA Rules ---
    with tab3:
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
                result = bot.create_yara_rule(rule_content)
                if result['status'] == 'success':
                    st.success(result['message'])
                else:
                    st.error(result['message'])
            if st.button("Explain Rule with Gemini AI"):
                if bot.genai_client:
                    ai_response = bot.get_ai_response(
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
