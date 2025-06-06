import streamlit as st
import google.generativeai as genai
import subprocess
import json
import re
import os
import tempfile
from datetime import datetime
import yara

st.set_page_config(
    page_title="CyberSec Assistant",
    page_icon="🛡️",
    layout="wide"
)

def parse_ports(output):
    # Parse ports table from nmap output
    lines = output.splitlines()
    port_lines = []
    details = {}
    parsing = False
    for i, line in enumerate(lines):
        if re.match(r"^PORT\s+STATE\s+SERVICE", line):
            parsing = True
            continue
        if parsing and (not line.strip() or line.startswith("Nmap done")):
            break
        if parsing and line.strip():
            parts = line.split()
            if len(parts) >= 3:
                port = parts[0]
                state = parts[1].capitalize()
                service = parts[2]
                info = " ".join(parts[3:]) if len(parts) > 3 else ""
                port_lines.append((port, state, service, info))
                details[port] = []
            elif port_lines:
                details[port_lines[-1][0]].append(line.strip())
    return port_lines, details

def nmap_commands():
    return {
        "network_map": ["nmap", "-sn"],                 # Fast ping scan
        "port_scan":   ["nmap", "-sT"],                 # TCP connect scan
        "service_scan": ["nmap", "-sV", "-sC"],         # Service & version
        "quick_host":  ["nmap", "-Pn"]                  # No ping, treat up
    }

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
        cmd_map = nmap_commands()
        if scan_type not in cmd_map:
            return {"error": "Invalid scan type."}
        command = cmd_map[scan_type] + [target]
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
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
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
- You provide guidance on scanning, recon, vulnerabilities, security tools.
- Always emphasize ethical use. Never assist with illegal activities.
Provide technical responses with practical examples when appropriate."""
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
        <p>This tool is designed for authorized security testing and research only.
        Ensure you have proper permission before scanning any systems. Unauthorized access to computer systems is illegal.</p>
    </div>
    """, unsafe_allow_html=True)

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
        target = st.text_input("Target (IP/Domain)", "google.com")
        scan_type = st.selectbox(
            "Nmap Scan Type",
            [
                "network_map",     # Fastest
                "port_scan",       # Fast, shows open ports
                "service_scan",    # Slow, advanced info
                "quick_host"       # No ping/Firewall Bypass
            ],
            format_func=lambda s: {
                "network_map": "Network Map (Ping Scan)",
                "port_scan": "Port Scan (Open Ports)",
                "service_scan": "Service Scan (Version/Default Scripts)",
                "quick_host": "No Ping/Firewall Bypass"
            }[s]
        )
        if st.button("Run Nmap Scan") and target:
            with st.spinner("Running scan..."):
                result = bot.run_nmap_scan(target, scan_type)
                if "scan_history" not in st.session_state:
                    st.session_state.scan_history = []
                st.session_state.scan_history.append({
                    "scan_type": scan_type,
                    "target": target,
                    "result": result
                })
                st.session_state.last_scan = result

    tab1, tab2, tab3 = st.tabs(["💬 Chat Assistant", "🔍 Scan Results", "📝 YARA Rules"])

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
                    response = bot.get_ai_response(prompt, context)
                    st.markdown(response)
                    st.session_state.messages.append({"role": "assistant", "content": response})

    with tab2:
        st.header("Scan Results")
        result = st.session_state.get("last_scan", None)
        output = result.get("stdout", "") if result else ""
        port_table, details = parse_ports(output) if output else ([], {})
        st.markdown(f"**Scan Command:** `{result['command']}`" if result else "")
        st.markdown(f"⏰ <b>Scan finished at:</b> {result.get('timestamp', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))}", unsafe_allow_html=True) if result else None

        if port_table:
            st.markdown("**Port Table**")
            st.write("| Port | State | Service | Info |")
            st.write("|------|-------|---------|------|")
            for p in port_table:
                port, state, service, info = p
                status = "🟢" if state.lower() == "open" else "🔴"
                st.write(f"| {status} {port} | {state} | {service} | {info} |")
        elif result:
            st.warning("No open ports detected.")

        # Safe port history comparison
        new_ports, closed_ports = set(), set()
        if (
            "scan_history" in st.session_state and
            len(st.session_state.scan_history) > 1 and
            port_table
        ):
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

        if result:
            st.markdown("<br><b>Full Nmap Output</b>", unsafe_allow_html=True)
            st.code(output, language="text")
        else:
            st.info("No scan results yet. Run a scan from the sidebar.")

    with tab3:
        st.header("YARA Rule Builder & File Scanner")
        rule_content = st.text_area(
            "YARA Rule",
            '''rule suspicious_string_rule
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
            height=300,
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
                    for uploaded_file in uploaded_files:
                        with tempfile.NamedTemporaryFile(delete=False) as tmp_file:
                            tmp_file.write(uploaded_file.read())
                            tmp_path = tmp_file.name
                        try:
                            result = bot.scan_with_yara(tmp_path, rule_content)
                            if result['status'] == 'success':
                                if result['matches']:
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

    st.markdown("---")
    st.markdown("""
    <div style="text-align: center; color: #666;">
        <p>🛡️ CyberSec Assistant - For Ethical Security Research Only</p>
        <p>Always ensure proper authorization before testing systems</p>
    </div>
    """, unsafe_allow_html=True)

if __name__ == "__main__":
    main()
