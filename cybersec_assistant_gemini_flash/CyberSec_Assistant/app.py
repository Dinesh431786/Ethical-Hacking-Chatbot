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
    .port-open {color: #22c55e;}
    .port-closed {color: #dc2626;}
    .riskline {color: #eab308;}
    .tiny {font-size: 12px;}
</style>
""", unsafe_allow_html=True)

# ---- Helper: Port Parsing ----
def parse_ports(output):
    port_table = []
    details = {}
    # Nmap's port table line format: PORT STATE SERVICE [VERSION]
    portline = re.compile(r"^(\d+/[a-z]+)\s+(\w+)\s+([\w\-?]+)\s*(.*)$")
    lines = output.splitlines()
    capture = False
    current_port = None
    for line in lines:
        if line.startswith("PORT"):
            capture = True
            continue
        if capture:
            if not line.strip() or line.startswith("Nmap done:"):
                capture = False
                continue
            m = portline.match(line)
            if m:
                port, state, service, extra = m.groups()
                port_table.append([port, state, service, extra])
                current_port = port
                details[current_port] = []
            elif current_port and line.strip().startswith("|"):
                details[current_port].append(line.strip())
    return port_table, details

# ---- Helper: Risk lines for some ports ----
def port_risk(port, service):
    risks = {
        "21/tcp": "FTP – Unencrypted, known for weak logins.",
        "22/tcp": "SSH – Brute force is common, keep patched.",
        "23/tcp": "Telnet – Insecure, avoid if possible.",
        "80/tcp": "HTTP – Unencrypted, outdated web servers are frequent targets.",
        "443/tcp": "HTTPS – Secure, but may hide malware or be misconfigured.",
        "3306/tcp": "MySQL – Default creds and RCE exploits possible.",
        "3389/tcp": "RDP – Brute force, bluekeep, patch required.",
    }
    return risks.get(port, "")

# ---- Helper: Quick links (Shodan, ExploitDB, etc) ----
def quick_links(port, domain):
    pnum = port.split("/")[0]
    base = f"https://www.shodan.io/search?query=port%3A{pnum}+{domain}"
    expl = f"https://www.exploit-db.com/search?port={pnum}"
    return (
        f"🌐 [Shodan: Search open {port} for {domain}]({base})  \n"
        f"🛡️ [ExploitDB/Port {pnum}]({expl})"
    )

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
                "network_map": ["nmap", "-sn", f"{target}/24"] if re.match(r'^\d+\.\d+\.\d+\.\d+$', target) else ["nmap", "-sn", target],
            }

            if scan_type not in scan_commands:
                return {"error": "Invalid scan type"}

            result = subprocess.run(
                scan_commands[scan_type],
                capture_output=True,
                text=True,
                timeout=120
            )

            return {
                "command": " ".join(scan_commands[scan_type]),
                "stdout": result.stdout,
                "stderr": result.stderr,
                "returncode": result.returncode,
                "scantime": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
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
    if 'scan_history' not in st.session_state:
        st.session_state.scan_history = []

    with st.sidebar:
        st.header("Configuration")
        gemini_key = st.text_input("Gemini API Key", type="password")
        if gemini_key and not st.session_state.bot.genai_client:
            if st.session_state.bot.initialize_gemini(gemini_key):
                st.success("Gemini API initialized!")

        st.header("Nmap Quick Scan")
        target = st.text_input("Target (IP/Domain)", placeholder="google.com or 192.168.1.1")
        scan_type = st.selectbox(
            "Nmap Scan Type",
            [
                "basic (Ping/Host Discovery)",
                "port_scan (Port Scan)",
                "service_scan (Service/Version Detection)",
                "network_map (Network Mapping - needs IP/CIDR)",
            ],
            format_func=lambda s: s.split(" ")[0].replace("_", " ").title()
        )
        scan_type_map = {
            "basic": "basic",
            "port_scan": "port_scan",
            "service_scan": "service_scan",
            "network_map": "network_map"
        }
        simple_scan_type = scan_type.split(" ")[0]

        if st.button("Run Nmap Scan") and target:
            with st.spinner("Running scan..."):
                result = st.session_state.bot.run_nmap_scan(target, scan_type_map[simple_scan_type])
                if 'stdout' in result and 'error' not in result:
                    st.session_state.scan_history.append(result)
                    st.session_state.last_scan = result
                else:
                    st.error(result.get('error', 'Unknown scan error'))

    tab1, tab2, tab3 = st.tabs(["💬 Chat Assistant", "🔍 Scan Results", "📝 YARA Rules"])

    # --- Chat Assistant ---
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

    # --- Scan Results ---
    with tab2:
        st.header("Scan Results")
        if 'last_scan' in st.session_state:
            result = st.session_state.last_scan
            output = result.get('stdout', '')
            port_table, details = parse_ports(output)
            st.markdown(f"**Scan Command:** `{result['command']}`")
            st.markdown(f"⏰ <b>Scan finished at:</b> {result['scantime']}", unsafe_allow_html=True)

            if port_table:
                st.markdown("<h5>Port Table</h5>", unsafe_allow_html=True)
                port_rows = ""
                for port, state, service, info in port_table:
                    color = "🟢" if state.lower() == "open" else "🔴"
                    port_rows += f"<tr><td>{color}</td><td><b>{port}</b></td><td>{state.title()}</td><td>{service}</td><td>{info}</td></tr>"
                st.markdown(
                    f"<table><tr><th></th><th>Port</th><th>State</th><th>Service</th><th>Info</th></tr>{port_rows}</table>",
                    unsafe_allow_html=True,
                )
                # Risk lines and quick links
                for port, state, service, info in port_table:
                    risk = port_risk(port, service)
                    if risk:
                        st.markdown(f'<span class="riskline">Risk on port {port}: {risk}</span>', unsafe_allow_html=True)
                    # Quick links for public ports (only for open ports)
                    if state.lower() == "open":
                        st.markdown(quick_links(port, target), unsafe_allow_html=True)
                # Show extra port details if available
                for port, data in details.items():
                    if data:
                        st.expander(f"More info on {port}").markdown("\n".join(data))
                open_ports = [p[0] for p in port_table if p[1].lower() == "open"]
                st.markdown(f"<b>{len(open_ports)} open ports:</b> {', '.join(open_ports)}", unsafe_allow_html=True)
            else:
                st.warning("No open ports detected.")

            # Network Map mode special display
            if result['command'].startswith("nmap -sn") and ("/24" in result['command'] or " " in target):
                hosts_up = re.findall(r"Nmap scan report for (.+)", output)
                st.markdown(f"<b>Hosts detected on network:</b> {len(hosts_up)}", unsafe_allow_html=True)
                for host in hosts_up:
                    st.markdown(f"- {host}")

            # Show scan diff if previous scan available
            if 'scan_history' in st.session_state and len(st.session_state.scan_history) > 1:
                last_ports = set(
                    p[0] for p in parse_ports(st.session_state.scan_history[-2].get('stdout',''))[0]
                )
                current_ports = set(p[0] for p in port_table)
                new_ports = current_ports - last_ports
                closed_ports = last_ports - current_ports
                if new_ports:
                    st.markdown(f"🆕 <b>New open ports since last scan:</b> {', '.join(new_ports)}", unsafe_allow_html=True)
                if closed_ports:
                    st.markdown(f"❌ <b>Ports now closed:</b> {', '.join(closed_ports)}", unsafe_allow_html=True)
            # Raw output
            with st.expander("Full Nmap Output"):
                st.code(output, language='text')

            # AI risk summary
            if st.button("🧠 Get AI Risk Summary for Results"):
                with st.spinner("Gemini analyzing scan..."):
                    ai_summary = st.session_state.bot.get_ai_response(
                        "Summarize risk and findings from this nmap output for a bug bounty hunter. Respond as a security engineer.",
                        output,
                    )
                    st.markdown(ai_summary)

        else:
            st.info("No scan results yet. Run a scan from the sidebar.")

    # --- YARA Rule Builder ---
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
