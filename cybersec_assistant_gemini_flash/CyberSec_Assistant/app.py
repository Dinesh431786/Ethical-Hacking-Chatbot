import streamlit as st
import google.generativeai as genai
import subprocess, tempfile, os, re
from datetime import datetime
import yara

st.set_page_config(page_title="CyberSec Assistant – Voxelta", page_icon="🛡️", layout="wide")

# -- Branding Header --
st.markdown("""
    <div style="background: linear-gradient(90deg, #1e3c72 0%, #2a5298 100%);
        padding:1.1rem 2rem 1.3rem 2rem; border-radius:10px;margin-bottom:2rem;box-shadow:0 4px 18px #1e3c7236;">
        <h2 style="color:#fff;margin:0;">🛡️ CyberSec Assistant <span style="font-size:0.7em; font-weight:normal;">(by Voxelta Private Limited)</span></h2>
        <div style="color:#ffe057;margin-top:6px;">
            <b>For Security Pros, Students & Auditors</b> — 
            <a style="color:#ffe057;" href="https://www.linkedin.com/in/dinesh-k-3199ab1b0/" target="_blank">Dinesh K</a>
        </div>
        <p style="color:#e0e0e0;margin:0;font-size:1.08em;">AI-Powered Recon & Vulnerability Toolkit — Beautiful, Powerful, Lightweight.</p>
    </div>
""", unsafe_allow_html=True)

st.markdown("""
    <div style="background:#fff3cd;padding:1rem 1.2rem;border:1px solid #ffeaa7;border-radius:8px;font-size:1em;">
        <b>⚠️ For authorized security research & learning only!</b> Never scan/test targets without permission.
    </div>
""", unsafe_allow_html=True)
st.write("")

# --- Tool info tooltips ---
TOOL_INFOS = {
    "Nmap": "Nmap is a powerful network scanner for port discovery and service detection.",
    "Nikto": "Nikto is a web server scanner for dangerous files and vulnerabilities.",
    "XSStrike": "XSStrike tests URLs for XSS vulnerabilities with advanced payloads.",
    "Hydra": "Hydra is a fast password brute-forcing tool for many services.",
    "YARA": "YARA is a malware pattern/rule-based file scanner used in forensics."
}

# --- Session state ---
if "history" not in st.session_state: st.session_state["history"] = []
if "bot" not in st.session_state: st.session_state["bot"] = None

# --- Gemini AI Bot Class ---
class CyberBot:
    def __init__(self):
        self.genai_client = None
    def init_gemini(self, api_key):
        try:
            genai.configure(api_key=api_key)
            self.genai_client = genai.GenerativeModel('gemini-1.5-flash')
            return True
        except Exception as e:
            st.error(f"Gemini error: {e}")
            return False
    def ai(self, text):
        if not self.genai_client: return ""
        try: return self.genai_client.generate_content(text).text
        except Exception as e: return f"AI Error: {e}"
    def yara_validate(self, rule):
        try:
            yara.compile(source=rule)
            return True, "Rule OK"
        except Exception as e:
            return False, str(e)
    def yara_scan(self, fpath, rule):
        try:
            rules = yara.compile(source=rule)
            return rules.match(fpath, timeout=30)
        except Exception as e:
            return f"Scan error: {e}"

# --- Util ---
def tool_exists(tool):
    from shutil import which
    return which(tool) is not None

def run_command(cmd, timeout=300):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout).stdout
    except Exception as e:
        return f"Error: {e}"

def nmap_scan_cmd(scan_type, target, custom_ports, custom_args):
    if scan_type == "Basic Ping": return ["nmap", "-sn", target]
    if scan_type == "Top Ports": return ["nmap", "-T4", "-F", target]
    if scan_type == "All Ports": return ["nmap", "-p-", target]
    if scan_type == "Service Detection": return ["nmap", "-sV", "-T4", target]
    if scan_type == "OS Detection": return ["nmap", "-O", target]
    if scan_type == "Aggressive": return ["nmap", "-A", "-T4", target]
    if scan_type == "Custom": return ["nmap"] + custom_args.split() + (["-p", custom_ports] if custom_ports else []) + [target]
    return ["nmap", target]

# -- Sidebar --
with st.sidebar:
    st.header("🔑 Gemini & Tools")
    gkey = st.text_input("Gemini API Key", type="password", help="Paste your Gemini/Google Generative AI API key")
    if gkey and not st.session_state["bot"]:
        st.session_state["bot"] = CyberBot()
        if st.session_state["bot"].init_gemini(gkey): st.success("Gemini Ready.")
    bot = st.session_state["bot"] or CyberBot()
    batch_mode = st.checkbox("Batch Mode (run all tools)", value=False)
    tool = st.selectbox("Single Tool", ["Nmap", "Nikto", "XSStrike", "Hydra", "YARA"])
    target = st.text_input("Target (IP/domain/url)", key="target", help="Enter a host, IP, or URL to scan.")

    # Per-tool config
    if tool == "Nmap" or batch_mode:
        scan_type = st.selectbox("Nmap Scan Type", [
            "Basic Ping", "Top Ports", "All Ports", "Service Detection",
            "OS Detection", "Aggressive", "Custom"
        ], help=TOOL_INFOS["Nmap"])
        custom_ports = st.text_input("Nmap Ports (if any)", key="nmap_ports", help="Comma-separated ports for custom scan.")
        custom_args = st.text_input("Extra Args (if custom)", key="nmap_args", help="e.g., -A -O")
    if tool == "Nikto" or batch_mode:
        nikto_args = st.text_input("Nikto Args", "", key="nikto_args", help=TOOL_INFOS["Nikto"])
    if tool == "XSStrike" or batch_mode:
        xs_args = st.text_input("XSStrike Args", "", key="xs_args", help=TOOL_INFOS["XSStrike"])
    if tool == "Hydra" or batch_mode:
        hydra_service = st.selectbox("Hydra Service", ["ssh", "ftp", "http-get", "rdp"], key="hydra_service", help=TOOL_INFOS["Hydra"])
        hydra_user = st.text_input("Hydra Username", key="hydra_user", help="Login username")
        hydra_wordlist = st.text_input("Hydra Wordlist", "/usr/share/wordlists/rockyou.txt", key="hydra_wordlist", help="Path to passwords list")

# -- Scan Action Panel --
st.markdown("#### 🎛️ Tool Panel")
st.info(TOOL_INFOS.get(tool, ""), icon="🔍")
st.write("")

scan_history = st.session_state["history"]

def highlight_findings(out):
    # Color critical findings (very basic regex, can be expanded)
    critical = re.findall(r"(vulnerab|error|xss|found|critical|fail|open)", out, re.I)
    if critical:
        return f"<div style='background:#fff4f3;padding:0.7em;border-radius:5px;color:#c00;font-weight:bold;'>Findings: {'/'.join(set(critical))}</div>"
    return ""

def count_vulns(out):
    c = len(re.findall(r"(vulnerab|CVE-|XSS|SQLi|open)", out, re.I))
    return f"**Vulnerability/Findings count:** {c}" if c else "**No obvious findings detected.**"

with st.container():
    colL, colR = st.columns([3, 2])
    with colL:
        if st.button("🚀 Run Scan(s)", use_container_width=True):
            results, timestamp = {}, datetime.now().strftime("%Y-%m-%d %H:%M")
            # -- Batch Mode --
            if batch_mode and target:
                # Nmap
                nmap_cmd = nmap_scan_cmd(scan_type, target, custom_ports, custom_args)
                results["Nmap"] = run_command(nmap_cmd)
                # Nikto
                results["Nikto"] = run_command(["nikto", "-h", target] + nikto_args.split())
                # XSStrike
                results["XSStrike"] = run_command(["python3", "XSStrike/xsstrike.py", "-u", target] + xs_args.split())
                # Hydra
                if hydra_user:
                    results["Hydra"] = run_command([
                        "hydra", "-l", hydra_user, "-P", hydra_wordlist, target, hydra_service
                    ])
                # Save history
                scan_history.append({"when": timestamp, "results": results, "target": target, "tools": list(results)})
            # -- Single Tool --
            elif target:
                if tool == "Nmap":
                    nmap_cmd = nmap_scan_cmd(scan_type, target, custom_ports, custom_args)
                    out = run_command(nmap_cmd)
                    results["Nmap"] = out
                elif tool == "Nikto":
                    cmd = ["nikto", "-h", target] + nikto_args.split()
                    out = run_command(cmd)
                    results["Nikto"] = out
                elif tool == "XSStrike":
                    cmd = ["python3", "XSStrike/xsstrike.py", "-u", target] + xs_args.split()
                    out = run_command(cmd)
                    results["XSStrike"] = out
                elif tool == "Hydra" and hydra_user:
                    cmd = ["hydra", "-l", hydra_user, "-P", hydra_wordlist, target, hydra_service]
                    out = run_command(cmd)
                    results["Hydra"] = out
                scan_history.append({"when": timestamp, "results": results, "target": target, "tools": list(results)})
            # -- Show Results
            for tname, out in results.items():
                st.markdown(f"#### {tname} Output")
                st.code(out)
                st.markdown(count_vulns(out))
                st.markdown(highlight_findings(out), unsafe_allow_html=True)
                if bot.genai_client and st.toggle(f"AI Analyze {tname}", key=f"{tname}_ai"):
                    st.success(bot.ai(out))
            # -- Export/Download
            scan_txt = "\n\n".join([f"{k}:\n{v}" for k,v in results.items()])
            st.download_button("Download Results (.txt)", scan_txt, file_name=f"scan_{timestamp}.txt")
    with colR:
        if scan_history:
            st.markdown("##### 📚 Session Scan History")
            idx = st.selectbox("View Previous", options=list(range(len(scan_history))), format_func=lambda i: scan_history[i]['when'])
            old = scan_history[idx]
            for t, out in old["results"].items():
                st.markdown(f"**{t} Output ({old['when']})**")
                st.code(out)
                st.markdown(count_vulns(out))
                st.markdown(highlight_findings(out), unsafe_allow_html=True)
                if bot.genai_client and st.toggle(f"AI Analyze {t} history", key=f"{t}_hist_ai"):
                    st.success(bot.ai(out))
            txt = "\n\n".join([f"{k}:\n{v}" for k,v in old["results"].items()])
            st.download_button("Export History Results (.txt)", txt, file_name=f"scan_{old['when'].replace(':','-')}.txt")

# --- YARA Always ---
st.markdown("---\n### 📝 YARA Rule Builder & File Scanner")
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
    height=250, key="yara_rule_box"
)
col1, col2 = st.columns(2)
with col1:
    if st.button("Validate Rule"):
        valid, msg = bot.yara_validate(rule_content)
        st.success(msg) if valid else st.error(msg)
    if st.button("Explain Rule with Gemini"):
        if bot.genai_client:
            st.markdown(bot.ai(rule_content))
        else:
            st.warning("Configure Gemini API first.")
with col2:
    files = st.file_uploader(
        "Upload files to scan", type=['exe', 'dll', 'pdf', 'doc', 'txt'],
        accept_multiple_files=True
    )
    if files and rule_content:
        if st.button("Scan Files"):
            for uploaded_file in files:
                with tempfile.NamedTemporaryFile(delete=False) as tmp_file:
                    tmp_file.write(uploaded_file.read())
                    tmp_path = tmp_file.name
                try:
                    matches = bot.yara_scan(tmp_path, rule_content)
                    if matches:
                        st.success(f"Matches in `{uploaded_file.name}`:")
                        for m in matches:
                            st.json({
                                "rule": m.rule,
                                "tags": m.tags,
                                "meta": m.meta,
                                "strings": [str(x) for x in m.strings]
                            })
                    else:
                        st.info(f"No matches found in `{uploaded_file.name}`.")
                finally:
                    os.unlink(tmp_path)

# --- Gemini Chat Assistant ---
with st.expander("💬 Gemini AI Chat Assistant", expanded=False):
    if 'messages' not in st.session_state:
        st.session_state.messages = []
    for message in st.session_state.messages:
        with st.chat_message(message["role"]):
            st.markdown(message["content"])
    if prompt := st.chat_input("Ask about security, tools, or results..."):
        st.session_state.messages.append({"role": "user", "content": prompt})
        with st.chat_message("user"):
            st.markdown(prompt)
        with st.chat_message("assistant"):
            with st.spinner("AI is thinking..."):
                resp = bot.ai(prompt)
                st.markdown(resp)
                st.session_state.messages.append({"role": "assistant", "content": resp})

st.markdown("---")
st.markdown("""
    <div style='text-align: center; color: #666; font-size: 0.98em;'>
        Made with ❤️ by <b>Voxelta Private Limited</b>.<br>
        <a href='https://www.linkedin.com/in/dinesh-k-3199ab1b0/' target='_blank'>Dinesh K on LinkedIn</a>
    </div>
""", unsafe_allow_html=True)
