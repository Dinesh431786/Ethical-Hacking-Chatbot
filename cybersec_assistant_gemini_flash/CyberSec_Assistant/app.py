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

# --- Core Functions ---

def parse_ports(output):
    port_table, details = [], {}
    in_table, current_port = False, None
    lines = output.splitlines()
    for line in lines:
        if line.strip().startswith("PORT "): in_table = True; continue
        if in_table:
            if not line.strip() or not re.match(r"^\d+/", line): in_table = False; continue
            parts = re.split(r'\s+', line, maxsplit=3)
            if len(parts) >= 3:
                port, state, service = parts[:3]
                info = parts[3] if len(parts) > 3 else ""
                port_table.append([port, state, service, info])
                details[port] = []
        port_match = re.match(r"^(\d+/[a-z]+)", line)
        if port_match: current_port = port_match.group(1)
        elif current_port and (line.strip().startswith('|') or line.strip().startswith('_')):
            if current_port in details: details[current_port].append(line.strip())
    return port_table, details

def service_icon(service):
    icons = {
        "http": "🌐", "https": "🔒", "ssh": "🔑", "ftp": "📁", "rdp": "🖥️",
        "smtp": "✉️", "dns": "🌎", "mysql": "🗄️", "postgresql": "🗄️", "smb": "🧩"
    }
    return icons.get(service, "🟢")

def advanced_port_tags(port_table):
    open_ports = [
        f"{service_icon(p[2])} <b>{p[0]}</b> <small>({p[2]})</small>"
        for p in port_table if p[1] == "open"
    ]
    if open_ports:
        tag_html = " ".join([
            f"<span style='background:#16a34a;color:#fff;border-radius:7px;padding:3px 10px;margin:2px 6px 2px 0;font-size:1rem;'>{p}</span>"
            for p in open_ports
        ])
        st.markdown(f"<b>{len(open_ports)} open ports:</b> {tag_html}", unsafe_allow_html=True)

def render_port_table(port_table):
    if not port_table: return "No open ports detected."
    md = "|  | Port | State | Service | Info |\n|:-:|:-----|:------|:--------|:-----|\n"
    for port, state, service, info in port_table:
        color = "🟢" if state == "open" else ("🔴" if state == "closed" else "⚪")
        md += f"| {color} | `{port}` | **{state.capitalize()}** | `{service}` | {info} |\n"
    return md

def export_report(text, filename):
    tmp_path = os.path.join(tempfile.gettempdir(), filename)
    with open(tmp_path, "w", encoding="utf-8") as f: f.write(text)
    with open(tmp_path, "rb") as f: st.download_button(f"⬇️ Download {filename}", f, file_name=filename, mime="text/plain")

def port_risk_info(port, service):
    common_ports = {
        "22": ("SSH", "High", "🔴", [
            "SSH is a frequent target for brute-force and credential attacks.",
            "If possible, restrict access by IP, disable password login, use keys, run on non-standard port, enable 2FA."
        ]),
        "3389": ("RDP", "Critical", "🛑", [
            "RDP is a top target for ransomware and brute-force attacks.",
            "Restrict to VPN, use NLA, monitor logs, never expose directly to the internet."
        ]),
        "23": ("Telnet", "Critical", "🛑", [
            "Telnet is insecure (plaintext). Should never be open to the internet.",
            "Replace with SSH or close. If legacy required, firewall restrict."
        ]),
        "445": ("SMB", "Critical", "🛑", [
            "SMB (Windows file sharing) is a worm/ransomware entry point.",
            "Block from internet, patch regularly, restrict to internal use only."
        ]),
        "80": ("HTTP", "Medium", "🟡", [
            "HTTP is unencrypted web. Test for web vulnerabilities (XSS, SQLi, etc).",
            "Redirect to HTTPS, use WAF, keep server/software patched."
        ]),
        "443": ("HTTPS", "Low", "🟢", [
            "HTTPS is encrypted, but web app vulns still apply.",
            "Check SSL config, scan for web app vulns, keep software up to date."
        ]),
        "3306": ("MySQL", "Critical", "🛑", [
            "Exposed databases are a top breach vector.",
            "Never expose MySQL to the internet; bind to localhost or firewall restrict."
        ]),
        "5432": ("PostgreSQL", "Critical", "🛑", [
            "Exposed databases are a top breach vector.",
            "Never expose PostgreSQL to the internet; bind to localhost or firewall restrict."
        ]),
        "21": ("FTP", "High", "🔴", [
            "FTP is unencrypted and can leak sensitive data.",
            "Use SFTP/FTPS, restrict access, avoid for sensitive info."
        ]),
        "25": ("SMTP", "Medium", "🟠", [
            "Mail servers are often abused for spam or relay.",
            "Restrict relay, use strong authentication, monitor for abuse."
        ])
    }
    portnum = port.split("/")[0]
    if portnum in common_ports:
        name, risk, color, advice = common_ports[portnum]
        return risk, color, advice
    else:
        return "Unknown", "⚪", [
            "Uncommon service. Research service and restrict if not needed.",
            "Monitor for unusual traffic or abuse."
        ]

def get_dashboard_summary(port_table):
    counts = {"Critical":0, "High":0, "Medium":0, "Low":0, "Unknown":0}
    port_advices = []
    for port, state, service, info in port_table:
        if state != "open":
            continue
        risk, color, advice = port_risk_info(port, service)
        counts[risk] = counts.get(risk, 0) + 1
        port_advices.append((port, service, risk, color, advice))
    return counts, port_advices

def dashboard_panel(port_advices, details):
    # "Fix first" box for critical/high
    criticals = [p for p in port_advices if p[2] in ("Critical", "High")]
    if criticals:
        st.markdown("## 🛑 Fix These First")
        for port, service, risk, color, advice in criticals:
            st.error(f"{color} **{port} ({service})** – {risk} risk")
            for line in advice:
                st.write(f"- {line}")

    st.markdown("## 🔍 Open Ports & Services Analysis")
    for port, service, risk, color, advice in port_advices:
        exp_title = f"{color} {port} ({service}) – {risk} risk"
        with st.expander(exp_title, expanded=risk in ["Critical","High"]):
            st.markdown("**Why is this risky?**")
            st.write(advice[0])
            st.markdown("**How to mitigate:**")
            st.write(advice[1])
            # Always show raw detail if present
            port_detail = details.get(port)
            if port_detail:
                st.markdown("**Raw Script Output:**")
                st.code("\n".join(port_detail), language="text")

def risk_overall(counts):
    if counts["Critical"]: return "Critical", "🛑"
    if counts["High"]: return "High", "🔴"
    if counts["Medium"]: return "Medium", "🟠"
    if counts["Low"]: return "Low", "🟢"
    return "Unknown", "⚪"

# --- Gemini & YARA Core Class ---

class EthicalHackingBot:
    def __init__(self): self.genai_client = None
    def initialize_gemini(self, api_key):
        try: genai.configure(api_key=api_key)
        except Exception as e: st.error(f"Gemini API error: {str(e)}"); return False
        self.genai_client = genai.GenerativeModel('gemini-1.5-flash'); return True
    def run_nmap_scan(self, target, scan_type):
        scan_commands = {
            "basic": ["nmap", "-sn", target],
            "port_scan": ["nmap", "-sT", target],
            "service_scan": ["nmap", "-sV", "-sC", target],
        }
        if scan_type not in scan_commands:
            return {"error": f"Scan failed: '{scan_type}'"}
        if not self.is_valid_target(target):
            return {"error": "Invalid target. Please provide a valid IP or domain."}
        try:
            cmd = scan_commands[scan_type]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            return {
                "command": " ".join(cmd),
                "stdout": result.stdout,
                "stderr": result.stderr,
                "returncode": result.returncode,
                "scan_type": scan_type
            }
        except Exception as e:
            return {"error": f"Scan failed: {str(e)}"}
    def create_yara_rule(self, rule_content):
        try: yara.compile(source=rule_content)
        except yara.SyntaxError as e: return {"status":"error", "message": f"YARA syntax error: {str(e)}"}
        except Exception as e: return {"status":"error", "message": f"Error: {str(e)}"}
        return {"status": "success", "message": "YARA rule compiled successfully"}
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
        if not self.genai_client: return "Configure Gemini API key first."
        try:
            system_prompt = """
You are an advanced cybersecurity assistant for professional researchers.
Explain scan results, highlight risk, port/attack surface, recommend next steps.
NEVER assist with illegal use. Use technical terms and always give real actionable context.
"""
            full_prompt = f"{system_prompt}\n\nContext: {context}\n\nUser Query: {user_input}"
            response = self.genai_client.generate_content(full_prompt)
            return response.text
        except Exception as e:
            return f"Gemini error: {str(e)}"

# --- Dashboard Tab ---

def show_dashboard(result):
    st.subheader("Scan Results & Security Dashboard")
    if not result:
        st.info("Run a scan to see results.")
        return
    if "error" in result:
        st.error(f"Scan Error: {result['error']}")
        return
    output = result.get("stdout", "")
    scan_type = result.get("scan_type", "")
    st.write(f"**Scan Command:** `{result.get('command','N/A')}`")
    st.write(f"⏰ <b>Scan finished at:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", unsafe_allow_html=True)
    if scan_type == "basic":
        if "Host is up" in output:
            st.success("🎯 Host is **up and reachable!**")
        elif "Host seems down" in output:
            st.error("❌ Host is **down or unreachable.**")
        else:
            st.info(output)
    else:
        port_table, details = parse_ports(output)
        counts, port_advices = get_dashboard_summary(port_table)
        risk, color = risk_overall(counts)
        st.markdown(f"<div style='font-size:1.2rem;margin-bottom:7px'>Overall Security Risk: <b>{color} {risk}</b></div>", unsafe_allow_html=True)
        advanced_port_tags(port_table)
        dashboard_panel(port_advices, details)
        st.markdown("---")
        st.markdown("### Port/Service Table")
        st.markdown(render_port_table(port_table), unsafe_allow_html=True)
        export_report(output, f"{scan_type}_nmap_report.txt")
        st.markdown("---")
        if st.button("🔍 AI Security Analysis", key="ai_context"):
            ai = st.session_state.bot.get_ai_response(
                "Give an actionable security summary of these Nmap scan results. Focus on open ports, their risks, and suggested next actions. Explain in clear language for a technical team.",
                output
            )
            with st.expander("Gemini AI Security Analysis", expanded=True):
                st.markdown(ai)
                export_report(ai, "gemini_ai_security_summary.txt")
        with st.expander("Raw Nmap Output"):
            st.code(output, language="text")

# --- Main UI ---

def main():
    st.markdown("<h1>🛡️ CyberSec Assistant</h1>", unsafe_allow_html=True)
    st.markdown("""
    <div style="background:#1e293b;padding:10px 18px;border-radius:10px;color:#eee;margin-bottom:14px;font-size:1rem">
    <b>⚠️ Strictly Ethical Use</b><br>
    This tool is for authorized research and defense only. Unauthorized scanning is illegal.
    </div>
    """, unsafe_allow_html=True)

    if 'bot' not in st.session_state:
        st.session_state.bot = EthicalHackingBot()

    with st.sidebar:
        st.header("Configure & Scan")
        gemini_key = st.text_input("Gemini API Key", type="password", key="gemini_api")
        if gemini_key and not st.session_state.bot.genai_client:
            if st.session_state.bot.initialize_gemini(gemini_key):
                st.success("Gemini API initialized!")
        st.divider()
        target = st.text_input("Target (IP or Domain)", placeholder="example.com or 192.168.1.1 (no http/https)", key="target")
        scan_type = st.radio("Scan Type", [
            "basic", "port_scan", "service_scan"
        ], horizontal=True, key="scan_type")
        if st.button("Run Nmap Scan", key="run_nmap") and target:
            with st.spinner("Scanning..."):
                result = st.session_state.bot.run_nmap_scan(target, scan_type)
                st.session_state.last_scan = result

    tabs = st.tabs(["📊 Scan Dashboard", "📝 YARA & File Analysis", "💬 AI Security Chat"])

    with tabs[0]:
        result = st.session_state.get("last_scan")
        show_dashboard(result)

    with tabs[1]:
        st.subheader("YARA Rule Builder & File Scanner")
        yara_templates = {
            "Suspicious String": f'''rule suspicious_string_rule
{{
    meta:
        description = "Detects suspicious string in files"
        author = "CyberSec Assistant"
        date = "{datetime.now().strftime('%Y-%m-%d')}"
    strings:
        $string1 = "malware"
    condition:
        $string1
}}''',
            "PE File (Windows EXE)": f'''rule pe_file_rule
{{
    meta:
        description = "Detects PE executable files"
        author = "CyberSec Assistant"
        date = "{datetime.now().strftime('%Y-%m-%d')}"
    strings:
        $mz = {{ 4D 5A }}
    condition:
        $mz at 0
}}''',
            "Custom (edit below)": ""
        }
        selected_template = st.selectbox("YARA Rule Template", list(yara_templates.keys()), key="yara_template")
        default_rule = yara_templates[selected_template] if selected_template != "Custom (edit below)" else ""
        rule_content = st.text_area("YARA Rule", value=default_rule, height=200, key="yara_rule")
        c1, c2 = st.columns(2)
        with c1:
            if st.button("✅ Validate Rule", key="validate_rule"):
                result = st.session_state.bot.create_yara_rule(rule_content)
                if result['status'] == 'success': st.success(result['message'])
                else: st.error(result['message'])
            if st.button("🤖 Explain Rule (Gemini)", key="explain_rule"):
                if st.session_state.bot.genai_client:
                    ai = st.session_state.bot.get_ai_response("Explain this YARA rule and its detection logic:", rule_content)
                    st.markdown(ai)
                else:
                    st.warning("Configure Gemini API key first.")
        with c2:
            uploaded_files = st.file_uploader(
                "Upload files to scan", type=['exe', 'dll', 'pdf', 'doc', 'txt'],
                accept_multiple_files=True, key="file_upload"
            )
            if uploaded_files and rule_content:
                if st.button("🔎 Scan Files", key="scan_files"):
                    matches_found = False
                    summary_txt = ""
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
                                    summary_txt += f"Matches in {uploaded_file.name}:\n"
                                    for match in result['matches']:
                                        st.write(f"**Rule:** `{match['rule']}`")
                                        summary_txt += f"- Rule: {match['rule']}\n"
                                        if match['tags']:
                                            st.write(f"**Tags:** {match['tags']}")
                                        if match['meta']:
                                            st.write(f"**Meta:** {match['meta']}")
                                        if match['strings']:
                                            for (offset, identifier, data) in match['strings']:
                                                st.write(
                                                    f"String `{identifier}` matched at offset `{offset}`: `{str(data)[:30]}...`"
                                                )
                                                summary_txt += f"  - String `{identifier}` at offset {offset}: {str(data)[:30]}\n"
                                else:
                                    st.info(f"No matches found in `{uploaded_file.name}`.")
                                    summary_txt += f"No matches in {uploaded_file.name}\n"
                            else:
                                st.error(f"Scan failed for `{uploaded_file.name}`: {result['message']}")
                        finally:
                            os.unlink(tmp_path)
                    if matches_found:
                        export_report(summary_txt, "yara_results.txt")
                    else:
                        st.warning("No matches found in any files.")

    with tabs[2]:
        st.subheader("AI Security Chat (Gemini)")
        if 'messages' not in st.session_state:
            st.session_state.messages = []
        if st.button("🧹 Clear Chat", key="clear_chat"):
            st.session_state.messages = []
            st.experimental_rerun()
        for message in st.session_state.messages:
            with st.chat_message(message["role"]):
                st.markdown(message["content"])
        if prompt := st.chat_input("Ask security, Nmap, YARA or anything cyber..."):
            st.session_state.messages.append({"role": "user", "content": prompt})
            with st.chat_message("user"):
                st.markdown(prompt)
            with st.chat_message("assistant"):
                with st.spinner("Gemini thinking..."):
                    context = ""
                    if 'last_scan' in st.session_state:
                        context = f"Recent scan results: {json.dumps(st.session_state.last_scan, indent=2)}"
                    response = st.session_state.bot.get_ai_response(prompt, context)
                    st.markdown(response)
                    st.session_state.messages.append({"role": "assistant", "content": response})

    st.markdown("---")
    st.markdown("<div style='text-align:center;color:#8b8b8b;font-size:0.95rem'>🛡️ CyberSec Assistant<br>Always work with permission.</div>", unsafe_allow_html=True)

if __name__ == "__main__":
    main()
