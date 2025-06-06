import streamlit as st
import google.generativeai as genai
import subprocess, tempfile, os, re
from datetime import datetime
import yara

st.set_page_config(page_title="CyberSec Assistant – Voxelta", page_icon="🛡️", layout="wide")

# -- Helper Functions --
def tool_exists(tool):  # Simple binary check
    from shutil import which
    return which(tool) is not None

def run_command(cmd, timeout=300):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout).stdout
    except Exception as e:
        return f"Error: {e}"

def ai_summary(bot, txt):  # Short Gemini summary
    return bot.ai(f"Summarize, explain, and give next steps:\n{txt}") if bot.genai_client else ""

def parse_scan_type(scan_type, target, custom_ports, custom_args):
    if scan_type == "Basic Ping":
        return ["nmap", "-sn", target]
    if scan_type == "Top Ports":
        return ["nmap", "-T4", "-F", target]
    if scan_type == "All Ports":
        return ["nmap", "-p-", target]
    if scan_type == "Service Detection":
        return ["nmap", "-sV", "-T4", target]
    if scan_type == "OS Detection":
        return ["nmap", "-O", target]
    if scan_type == "Aggressive":
        return ["nmap", "-A", "-T4", target]
    if scan_type == "Custom":
        return ["nmap"] + custom_args.split() + (["-p", custom_ports] if custom_ports else []) + [target]
    return ["nmap", target]

# -- Bot Class --
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

bot = st.session_state.setdefault('bot', CyberBot())

# -- Sidebar: Tool & Scan Selection --
with st.sidebar:
    st.header("🔑 Gemini API & Tool Selection")
    gkey = st.text_input("Gemini API Key", type="password")
    if gkey and not bot.genai_client:
        if bot.init_gemini(gkey): st.success("Gemini Ready.")
    batch_mode = st.checkbox("Batch Mode (all tools)", value=False)
    main_tools = [
        "Nmap", "Nikto", "XSStrike", "Hydra", "Subfinder", "theHarvester", "YARA"
    ]
    tool = st.selectbox("Single Tool", main_tools)
    target = st.text_input("Target (IP/domain/url/email)", key="target")

# -- Arguments Per Tool --
args = {}
if tool == "Nmap" or batch_mode:
    scan_type = st.selectbox("Nmap Scan Type", [
        "Basic Ping", "Top Ports", "All Ports", "Service Detection",
        "OS Detection", "Aggressive", "Custom"
    ])
    custom_ports = st.text_input("Custom Ports (if any)", key="nmap_ports")
    custom_args = st.text_input("Extra Args (if custom)", key="nmap_args")
    args['Nmap'] = (scan_type, custom_ports, custom_args)
if tool == "Nikto" or batch_mode:
    args['Nikto'] = st.text_input("Nikto Args", "", key="nikto_args")
if tool == "XSStrike" or batch_mode:
    args['XSStrike'] = st.text_input("XSStrike Args", "", key="xsstrike_args")
if tool == "Hydra" or batch_mode:
    hydra_service = st.selectbox("Hydra Service", ["ssh", "ftp", "http-get", "rdp"], key="hydra_service")
    hydra_user = st.text_input("Hydra Username", key="hydra_user")
    hydra_wordlist = st.text_input("Hydra Wordlist", "/usr/share/wordlists/rockyou.txt", key="hydra_wordlist")
    args['Hydra'] = (hydra_service, hydra_user, hydra_wordlist)
if tool == "Subfinder" or batch_mode:
    args['Subfinder'] = st.text_input("Subfinder Args", "", key="subfinder_args")
if tool == "theHarvester" or batch_mode:
    args['theHarvester'] = st.text_input("theHarvester Args", "-b all -l 20", key="harvester_args")

# -- Batch and Single Mode Scan Buttons --
if st.button("🚀 Run Scan(s)"):
    outputs = {}
    if batch_mode and target:
        # Nmap
        scan_type, custom_ports, custom_args = args['Nmap']
        nmap_cmd = parse_scan_type(scan_type, target, custom_ports, custom_args)
        outputs['Nmap'] = run_command(nmap_cmd)
        # Nikto
        outputs['Nikto'] = run_command(["nikto", "-h", target] + args['Nikto'].split())
        # XSStrike
        outputs['XSStrike'] = run_command(["python3", "XSStrike/xsstrike.py", "-u", target] + args['XSStrike'].split())
        # Hydra (optional, needs valid username/wordlist/service)
        if args['Hydra'][1]:
            outputs['Hydra'] = run_command(["hydra", "-l", args['Hydra'][1], "-P", args['Hydra'][2], f"{target}", args['Hydra'][0]])
        # Subfinder
        outputs['Subfinder'] = run_command(["subfinder", "-d", target] + args['Subfinder'].split())
        # theHarvester
        outputs['theHarvester'] = run_command(["theHarvester", "-d", target] + args['theHarvester'].split())
        # Show all
        for k, v in outputs.items():
            st.markdown(f"### {k} Output")
            st.code(v)
            if bot.genai_client and st.checkbox(f"AI Analyze {k}", key=k):
                st.markdown(ai_summary(bot, v))
    elif target:
        if tool == "Nmap":
            scan_type, custom_ports, custom_args = args['Nmap']
            cmd = parse_scan_type(scan_type, target, custom_ports, custom_args)
            out = run_command(cmd)
            st.code(out)
            if bot.genai_client and st.checkbox("AI Analyze"):
                st.markdown(ai_summary(bot, out))
        elif tool == "Nikto":
            cmd = ["nikto", "-h", target] + args['Nikto'].split()
            out = run_command(cmd)
            st.code(out)
            if bot.genai_client and st.checkbox("AI Analyze"):
                st.markdown(ai_summary(bot, out))
        elif tool == "XSStrike":
            cmd = ["python3", "XSStrike/xsstrike.py", "-u", target] + args['XSStrike'].split()
            out = run_command(cmd)
            st.code(out)
            if bot.genai_client and st.checkbox("AI Analyze"):
                st.markdown(ai_summary(bot, out))
        elif tool == "Hydra":
            hydra_service, hydra_user, hydra_wordlist = args['Hydra']
            if hydra_user:
                cmd = ["hydra", "-l", hydra_user, "-P", hydra_wordlist, target, hydra_service]
                out = run_command(cmd)
                st.code(out)
                if bot.genai_client and st.checkbox("AI Analyze"):
                    st.markdown(ai_summary(bot, out))
            else:
                st.info("Hydra username required.")
        elif tool == "Subfinder":
            cmd = ["subfinder", "-d", target] + args['Subfinder'].split()
            out = run_command(cmd)
            st.code(out)
        elif tool == "theHarvester":
            cmd = ["theHarvester", "-d", target] + args['theHarvester'].split()
            out = run_command(cmd)
            st.code(out)
        elif tool == "YARA":
            pass  # below

# --- YARA tab always available ---
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
    height=300, key="yara_rule_box"
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
                st.session_state.messages.append({"role": "assistant", "content": resp)

st.markdown("---")
st.markdown("""
    <div style='text-align: center; color: #666; font-size: 0.96em;'>
        Made with ❤️ by <b>Voxelta Private Limited</b>.<br>
        <a href='https://www.linkedin.com/in/dinesh-k-3199ab1b0/' target='_blank'>Dinesh K on LinkedIn</a>
    </div>
""", unsafe_allow_html=True)
