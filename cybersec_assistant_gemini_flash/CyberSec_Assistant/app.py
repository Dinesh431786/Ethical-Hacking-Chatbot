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
import requests

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
        self.conversation_history = []

    def initialize_gemini(self, api_key):
        try:
            genai.configure(api_key=api_key)
            self.genai_client = genai.GenerativeModel('gemini-1.5-flash')
            return True
        except Exception as e:
            st.error(f"Failed to initialize Gemini API: {str(e)}")
            return False

    def run_nmap_scan(self, target, scan_type="basic"):
        try:
            if not self.is_valid_target(target):
                return {"error": "Invalid target. Please provide a valid IP or domain."}

            scan_commands = {
                "basic": ["nmap", "-sn", target],
                "port_scan": ["nmap", "-sS", "-O", target],
                "service_scan": ["nmap", "-sV", "-sC", target],
                "vuln_scan": ["nmap", "--script", "vuln", target],
                "stealth": ["nmap", "-sS", "-f", "-T2", target]
            }

            if scan_type not in scan_commands:
                return {"error": "Invalid scan type"}

            result = subprocess.run(
                scan_commands[scan_type],
                capture_output=True,
                text=True,
                timeout=300
            )

            return {
                "command": " ".join(scan_commands[scan_type]),
                "stdout": result.stdout,
                "stderr": result.stderr,
                "returncode": result.returncode
            }

        except subprocess.TimeoutExpired:
            return {"error": "Scan timed out after 5 minutes"}
        except Exception as e:
            return {"error": f"Scan failed: {str(e)}"}

    def create_yara_rule(self, rule_content):
        try:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.yar', delete=False) as f:
                f.write(rule_content)
                rule_file = f.name

            yara.compile(filepath=rule_file)
            os.unlink(rule_file)

            return {"status": "success", "message": "YARA rule compiled successfully"}

        except yara.SyntaxError as e:
            return {"status": "error", "message": f"YARA syntax error: {str(e)}"}
        except Exception as e:
            return {"status": "error", "message": f"Error: {str(e)}"}

    def scan_with_yara(self, file_path, rule_content):
        try:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.yar', delete=False) as f:
                f.write(rule_content)
                rule_file = f.name

            rules = yara.compile(filepath=rule_file)
            matches = rules.match(file_path)
            os.unlink(rule_file)

            return {
                "status": "success",
                "matches": [{"rule": match.rule, "tags": match.tags} for match in matches]
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

        st.header("Quick Tools")
        target = st.text_input("Target (IP/Domain)", placeholder="192.168.1.1 or example.com")
        scan_type = st.selectbox("Nmap Scan Type", ["basic", "port_scan", "service_scan", "vuln_scan", "stealth"])

        if st.button("Run Nmap Scan") and target:
            with st.spinner("Running scan..."):
                result = st.session_state.bot.run_nmap_scan(target, scan_type)
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

                    response = st.session_state.bot.get_ai_response(prompt, context)
                    st.markdown(response)
                    st.session_state.messages.append({"role": "assistant", "content": response})

    with tab2:
        st.header("Scan Results")
        if 'last_scan' in st.session_state:
            result = st.session_state.last_scan
            if 'error' in result:
                st.error(f"Scan Error: {result['error']}")
            else:
                st.markdown(f"**Command:** `{result.get('command', 'N/A')}`")
                if result.get('stdout'):
                    st.markdown("**Output:**")
                    st.code(result['stdout'], language='text')
                if result.get('stderr'):
                    st.markdown("**Errors:**")
                    st.code(result['stderr'], language='text')

                if st.button("Get AI Analysis of Results"):
                    with st.spinner("Analyzing results..."):
                        analysis = st.session_state.bot.get_ai_response(
                            "Analyze these nmap scan results and provide insights:",
                            result.get('stdout', '')
                        )
                        st.markdown("**AI Analysis:**")
                        st.markdown(analysis)
        else:
            st.info("No scan results yet. Run a scan from the sidebar.")

    with tab3:
        st.header("YARA Rule Builder")
        col1, col2 = st.columns(2)

        with col1:
            st.subheader("Create YARA Rule")
            rule_name = st.text_input("Rule Name", "sample_rule")
            rule_description = st.text_area("Description", "Sample YARA rule")
            sample_rule = f'''rule {rule_name}
{{
    meta:
        description = "{rule_description}"
        author = "CyberSec Assistant"
        date = "{datetime.now().strftime('%Y-%m-%d')}"
    strings:
        $string1 = "suspicious_string"
        $hex = {{ 4D 5A 90 00 }}
    condition:
        $string1 or $hex
}}'''
            rule_content = st.text_area("YARA Rule", sample_rule, height=300)
            if st.button("Validate Rule"):
                result = st.session_state.bot.create_yara_rule(rule_content)
                if result['status'] == 'success':
                    st.success(result['message'])
                else:
                    st.error(result['message'])

        with col2:
            st.subheader("File Scanner")
            uploaded_file = st.file_uploader("Upload file to scan", type=['exe', 'dll', 'pdf', 'doc', 'txt'])
            if uploaded_file and rule_content:
                if st.button("Scan File"):
                    with tempfile.NamedTemporaryFile(delete=False) as tmp_file:
                        tmp_file.write(uploaded_file.read())
                        tmp_path = tmp_file.name
                    try:
                        result = st.session_state.bot.scan_with_yara(tmp_path, rule_content)
                        if result['status'] == 'success':
                            if result['matches']:
                                st.success("Matches found!")
                                for match in result['matches']:
                                    st.write(f"Rule: {match['rule']}, Tags: {match['tags']}")
                            else:
                                st.info("No matches found.")
                        else:
                            st.error(result['message'])
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