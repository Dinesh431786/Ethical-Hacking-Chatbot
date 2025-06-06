import streamlit as st
import google.generativeai as genai
import subprocess, os, re, tempfile, json
from datetime import datetime
import yara

# ---- Branding ----
VOXELTA_LOGO = "https://i.imgur.com/voxel-logo.png"  # Replace with your logo if needed
AUTHOR_LINKEDIN = "https://www.linkedin.com/in/dinesh-k-3199ab1b0/"
VOXELTA_BRAND = "Voxelta Private Limited"

st.set_page_config(page_title="CyberSec Assistant – Voxelta", page_icon="🛡️", layout="wide")

st.markdown(f"""
<div style='display:flex;align-items:center;gap:16px;background:linear-gradient(90deg,#1e3c72 0%,#2a5298 100%);padding:1.1rem 2rem;border-radius:10px;margin-bottom:2rem;'>
    <img src="{VOXELTA_LOGO}" width="48" style="border-radius:6px;">
    <div>
        <h1 style="color:#fff;margin:0;">🛡️ CyberSec Assistant</h1>
        <div style="color:#ffe057;font-weight:bold;">by {VOXELTA_BRAND} &nbsp;|&nbsp;
        <a style="color:#ffe057;" href="{AUTHOR_LINKEDIN}" target="_blank">Dinesh K</a></div>
        <p style="color:#e0e0e0;font-size:1.1em;margin:0;">AI-Powered Advanced Security & Recon Platform</p>
    </div>
</div>
""", unsafe_allow_html=True)

st.markdown("""
    <div style="background:#fff3cd;padding:1rem;border:1px solid #ffeaa7;border-radius: 8px;">
        <b>⚠️ For authorized security research and educational use only!</b><br>
        Never scan or test targets without explicit permission.
    </div>
""", unsafe_allow_html=True)
st.write("")

# ---- Utility Functions ----
def tool_exists(tool):
    try:
        subprocess.run([tool, "--version"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)
        return True
    except:
        return False

def stream_command(cmd):
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    out, err = "", ""
    for line in proc.stdout:
        out += line
        st.text(line.rstrip())
    err = proc.stderr.read()
    if err:
        st.warning(f"[stderr]: {err}")
        out += "\n" + err
    return out

def parse_nmap_output(output):
    ports = re.findall(r"(\d+)/tcp\s+open", output)
    return f"Open TCP Ports: {', '.join(ports)}" if ports else "No open ports found."

def parse_nikto_output(output):
    vulns = re.findall(r"\+\s+OSVDB-\d+:\s+([^\n]+)", output)
    return "Vulnerabilities:\n" + "\n".join(f"- {v}" for v in vulns) if vulns else "No critical vulns detected."

def parse_xsstrike_output(output):
    xss = re.findall(r"\[Vulnerable\]", output)
    return f"Potential XSS found: {len(xss)} locations." if xss else "No XSS found."

def html_report(scans, ai_summaries, branding=VOXELTA_BRAND):
    html = f"<h2>CyberSec Report – {branding}</h2><hr>"
    for tool, entry in scans.items():
        html += f"<h3>{tool}</h3>"
        html += f"<b>Command:</b> <code>{entry['cmd']}</code><br>"
        html += f"<pre style='background:#222;color:#fff;padding:1em;border-radius:5px;'>{entry['output']}</pre>"
        if ai_summaries.get(tool):
            html += f"<b>AI Insights:</b><div style='background:#eef;padding:0.7em;border-radius:5px;'>{ai_summaries[tool]}</div>"
    html += f"<hr><footer style='font-size:0.9em;color:#888;'>Secured &amp; Analyzed by {branding} | {datetime.now().strftime('%Y-%m-%d %H:%M')}</footer>"
    return html

# ---- Bot Class ----
class AdvancedBot:
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
        if not self.genai_client: return "Gemini not configured."
        try:
            r = self.genai_client.generate_content(text)
            return r.text
        except Exception as e:
            return f"AI Error: {e}"
    def yara_validate(self, rule):  # unchanged from earlier
        try:
            yara.compile(source=rule)
            return True, "Rule OK"
        except Exception as e:
            return False, str(e)
    def yara_scan(self, fpath, rule):
        try:
            rules = yara.compile(source=rule)
            matches = rules.match(fpath, timeout=30)
            return matches
        except Exception as e:
            return f"Scan error: {e}"

bot = st.session_state.setdefault('bot', AdvancedBot())
if 'history' not in st.session_state:
    st.session_state.history = {}

# ---- Sidebar ----
with st.sidebar:
    st.header("Gemini & Tool Modes")
    gkey = st.text_input("Gemini API Key", type="password")
    if gkey and not bot.genai_client:
        if bot.init_gemini(gkey):
            st.success("Gemini Ready.")
    batch_mode = st.checkbox("Batch Mode (run all tools)", value=False)
    tool = st.selectbox("Single Tool", ["Nmap", "Nikto", "XSStrike", "Subfinder", "theHarvester", "YARA"])
    target = st.text_input("Target (IP/domain/url/email)", key="target")
    save_profile = st.text_input("Save arguments as profile (optional)")
    load_profile = st.selectbox("Load profile", ["None"] + list(st.session_state.history.keys()))

# ---- Tool Arguments (per tool or batch) ----
arguments = {}
if tool == "Nmap" or batch_mode:
    arguments['Nmap'] = {
        "args": st.text_input("Nmap options", "-T4 -F"),
        "ports": st.text_input("Nmap ports", "21,22,80,443,3306")
    }
if tool == "Nikto" or batch_mode:
    arguments['Nikto'] = {
        "args": st.text_input("Nikto options", "", key="nikto_args")
    }
if tool == "XSStrike" or batch_mode:
    arguments['XSStrike'] = {
        "args": st.text_input("XSStrike options", "", key="xsstrike_args")
    }
if tool == "Subfinder" or batch_mode:
    arguments['Subfinder'] = {
        "args": st.text_input("Subfinder options", "", key="subf_args")
    }
if tool == "theHarvester" or batch_mode:
    arguments['theHarvester'] = {
        "args": st.text_input("theHarvester options", "-b all -l 20", key="harv_args")
    }

# ---- Scan/Run Button ----
def run_and_save(tool_name, cmd):
    st.info(f"Running: {' '.join(cmd)}")
    out = bot.ai(f"Running command: {' '.join(cmd)}") if not tool_exists(cmd[0]) else ""
    if not out:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=300).stdout
    ai_sum = bot.ai(f"Analyze this output:\n{out}")
    st.session_state.history[tool_name + " " + datetime.now().strftime("%H:%M:%S")] = {
        "cmd": " ".join(cmd), "output": out, "ai": ai_sum
    }
    st.code(out, language='text')
    if ai_sum: st.markdown(f"**AI Analysis:** {ai_sum}")

if st.button("🚀 Run Scan(s)"):
    scans, ai_summaries = {}, {}
    # BATCH MODE
    if batch_mode and target:
        # Nmap
        nmap_cmd = ["nmap"] + arguments['Nmap']["args"].split() + ["-p", arguments['Nmap']["ports"], target]
        out_nmap = subprocess.run(nmap_cmd, capture_output=True, text=True).stdout
        scans["Nmap"] = {"cmd": " ".join(nmap_cmd), "output": out_nmap}
        ai_summaries["Nmap"] = bot.ai(f"Parse and summarize this Nmap output:\n{out_nmap}")

        # Nikto
        nikto_cmd = ["nikto", "-h", target] + arguments['Nikto']["args"].split()
        out_nikto = subprocess.run(nikto_cmd, capture_output=True, text=True).stdout
        scans["Nikto"] = {"cmd": " ".join(nikto_cmd), "output": out_nikto}
        ai_summaries["Nikto"] = bot.ai(f"Parse and summarize this Nikto output:\n{out_nikto}")

        # XSStrike
        xs_cmd = ["python3", "XSStrike/xsstrike.py", "-u", target] + arguments['XSStrike']["args"].split()
        out_xs = subprocess.run(xs_cmd, capture_output=True, text=True).stdout
        scans["XSStrike"] = {"cmd": " ".join(xs_cmd), "output": out_xs}
        ai_summaries["XSStrike"] = bot.ai(f"Parse and summarize this XSStrike output:\n{out_xs}")

        # Subfinder
        if tool_exists("subfinder"):
            subf_cmd = ["subfinder", "-d", target] + arguments['Subfinder']["args"].split()
            out_subf = subprocess.run(subf_cmd, capture_output=True, text=True).stdout
            scans["Subfinder"] = {"cmd": " ".join(subf_cmd), "output": out_subf}
            ai_summaries["Subfinder"] = bot.ai(f"Parse and summarize this Subfinder output:\n{out_subf}")

        # theHarvester
        if tool_exists("theHarvester"):
            harv_cmd = ["theHarvester", "-d", target] + arguments['theHarvester']["args"].split()
            out_harv = subprocess.run(harv_cmd, capture_output=True, text=True).stdout
            scans["theHarvester"] = {"cmd": " ".join(harv_cmd), "output": out_harv}
            ai_summaries["theHarvester"] = bot.ai(f"Parse and summarize this theHarvester output:\n{out_harv}")

        # Show all results
        for k in scans:
            st.markdown(f"### {k} Output")
            st.code(scans[k]["output"], language='text')
            if ai_summaries[k]: st.markdown(f"**AI Summary:** {ai_summaries[k]}")
        # HTML report
        html = html_report(scans, ai_summaries)
        st.download_button("Download HTML Report", html, file_name="cybersec_report_voxelta.html")
    # SINGLE TOOL MODE
    elif target:
        if tool == "Nmap":
            cmd = ["nmap"] + arguments['Nmap']["args"].split() + ["-p", arguments['Nmap']["ports"], target]
            run_and_save("Nmap", cmd)
        elif tool == "Nikto":
            cmd = ["nikto", "-h", target] + arguments['Nikto']["args"].split()
            run_and_save("Nikto", cmd)
        elif tool == "XSStrike":
            cmd = ["python3", "XSStrike/xsstrike.py", "-u", target] + arguments['XSStrike']["args"].split()
            run_and_save("XSStrike", cmd)
        elif tool == "Subfinder":
            cmd = ["subfinder", "-d", target] + arguments['Subfinder']["args"].split()
            run_and_save("Subfinder", cmd)
        elif tool == "theHarvester":
            cmd = ["theHarvester", "-d", target] + arguments['theHarvester']["args"].split()
            run_and_save("theHarvester", cmd)
        elif tool == "YARA":
            # handled below
            pass

# ---- Session History / Profile Loader ----
st.markdown("### 🕑 Scan History")
if st.session_state.history:
    chosen = st.selectbox("Review Previous Scans", list(st.session_state.history.keys()))
    entry = st.session_state.history[chosen]
    st.write(f"**Command:** `{entry['cmd']}`")
    st.code(entry['output'], language='text')
    if entry['ai']:
        st.markdown(f"**AI Analysis:** {entry['ai']}")

# ---- YARA Scanner (also accessible in batch, but shown always) ----
if tool == "YARA" or batch_mode:
    st.markdown("## 📝 YARA Rule Builder & Scanner")
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

# ---- Gemini Chat Assistant ----
with st.expander("💬 Gemini AI Chat Assistant", expanded=False):
    if 'messages' not in st.session_state:
        st.session_state.messages = []
    for message in st.session_state.messages:
        with st.chat_message(message["role"]):
            st.markdown(message["content"])
    if prompt := st.chat_input("Ask anything about results, tools, or security..."):
        st.session_state.messages.append({"role": "user", "content": prompt})
        with st.chat_message("user"):
            st.markdown(prompt)
        with st.chat_message("assistant"):
            with st.spinner("AI is thinking..."):
                resp = bot.ai(prompt)
                st.markdown(resp)
                st.session_state.messages.append({"role": "assistant", "content": resp})

st.markdown("---")
st.markdown(f"""
    <div style='text-align: center; color: #666; font-size: 0.96em;'>
        Made with ❤️ by <b>{VOXELTA_BRAND}</b>.<br>
        <a href='{AUTHOR_LINKEDIN}' target='_blank'>Dinesh K on LinkedIn</a>
    </div>
""", unsafe_allow_html=True)
