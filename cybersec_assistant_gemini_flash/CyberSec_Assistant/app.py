import streamlit as st
import nmap
import yara
import tempfile
import os
import google.generativeai as genai
from datetime import datetime

# -- Branding/Header --
st.set_page_config(page_title="Voxelta Security Toolkit", page_icon="🛡️", layout="wide")
st.markdown("""
<style>
.card {background: #f7fafd; border-radius: 12px; box-shadow: 0 2px 14px #d2e5fa44; padding: 1.5em 2em; margin-bottom: 2em;}
.ai-explain {background: #eefbe9; border-radius: 10px; margin-top: 1.2em; padding: 1.1em 1.5em; font-size: 1.08em;}
.bigout {font-size: 1.15em; background: #f5f8ff; border-radius: 9px; padding: 1.1em 1.5em; margin: 1.2em 0 0.8em 0;}
h2, h3 {margin-top: 0;}
</style>
<div style="background: linear-gradient(90deg,#1e3c72 0%,#2a5298 100%);
padding:1.2rem 2rem 1.1rem 2rem; border-radius:13px; margin-bottom:1.4rem;">
  <h2 style="color:#fff;margin-bottom:0;">🛡️ Voxelta Security Toolkit</h2>
  <div style="color:#ffe057;">For Ethical Hackers & Researchers |
    <a style="color:#ffe057;" href="https://www.linkedin.com/in/dinesh-k-3199ab1b0/" target="_blank">Dinesh K</a>
  </div>
</div>
""", unsafe_allow_html=True)

# -- Gemini Helper --
class GeminiBot:
    def __init__(self):
        self.client = None
    def init(self, key):
        try:
            genai.configure(api_key=key)
            self.client = genai.GenerativeModel('gemini-1.5-flash')
            return True
        except Exception as e:
            st.error(f"Gemini error: {e}")
            return False
    def analyze(self, text, prompt=None):
        if not self.client: return ""
        try:
            return self.client.generate_content((prompt or "") + "\n\n" + text).text
        except Exception as e:
            return f"AI Error: {e}"

if "gemini" not in st.session_state: st.session_state["gemini"] = None
if "gemini_init" not in st.session_state: st.session_state["gemini_init"] = False

# -- Sidebar: Tool Selector & Gemini --
with st.sidebar:
    st.header("⚙️ Tool & AI Setup")
    gkey = st.text_input("Gemini API Key", type="password")
    if gkey and not st.session_state["gemini_init"]:
        st.session_state["gemini"] = GeminiBot()
        if st.session_state["gemini"].init(gkey):
            st.success("Gemini Connected!")
            st.session_state["gemini_init"] = True

    tool = st.radio("Choose Tool", [
        "Nmap Scanner",
        "YARA Scanner"
    ], format_func=lambda x: {
        "Nmap Scanner": "🛡️ Nmap Scanner",
        "YARA Scanner": "🦠 YARA Scanner"
    }[x])

# -- Nmap Output Formatter (Table for Port/Stealth) --
def pretty_nmap_csv(csv_str):
    # Only show table for port/stealth, otherwise just plain
    lines = [x for x in csv_str.splitlines() if x.strip()]
    if len(lines) < 2 or lines[0].startswith("host;"):
        return st.code(csv_str, language="text")
    headers = lines[0].split(";")
    st.markdown('<div class="bigout">', unsafe_allow_html=True)
    st.write("**Scan Results:**")
    st.table([dict(zip(headers, l.split(";"))) for l in lines[1:]])
    st.markdown('</div>', unsafe_allow_html=True)

# -- Nmap PANEL --
if tool == "Nmap Scanner":
    st.markdown('<div class="card">', unsafe_allow_html=True)
    st.subheader("🛡️ Nmap Scanner")
    scan_types = {
        "Basic": "-sn",
        "Port Scan": "-T4 -F",
        "Stealth": "-sS"
    }
    scan = st.selectbox("Scan Type", list(scan_types.keys()))
    target = st.text_input("Target (IP/domain)", value="scanme.nmap.org")
    ports = ""
    if scan in ["Port Scan", "Stealth"]:
        ports = st.text_input("Ports (comma-separated)", value="21,22,80,443", key="ports")
    run = st.button("Run Nmap Scan")
    if run:
        if not target:
            st.error("Please enter a target!")
        else:
            args = scan_types[scan]
            if ports and scan in ["Port Scan", "Stealth"]:
                args += f" -p {ports}"
            st.info(f"Running: `nmap {args} {target}`")
            nm = nmap.PortScanner()
            try:
                nm.scan(target, arguments=args)
                result = nm.csv()
                # Show as pretty table for port/stealth, code for basic
                if scan == "Basic":
                    st.markdown('<div class="bigout">', unsafe_allow_html=True)
                    st.code(result or "No results.", language="text")
                    st.markdown('</div>', unsafe_allow_html=True)
                else:
                    pretty_nmap_csv(result)
                st.download_button("⬇️ Download Result (.txt)", result, file_name=f"nmap_{scan}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
                # Gemini Explain
                if st.session_state["gemini"]:
                    if st.button("💡 Gemini: Explain Result"):
                        with st.spinner("Gemini is analyzing..."):
                            explain = st.session_state["gemini"].analyze(result, prompt=f"Explain this Nmap {scan} scan output for a cyber security expert. Show port/service risks and recommendations.")
                        st.markdown(f'<div class="ai-explain"><b>Gemini Explanation:</b><br>{explain}</div>', unsafe_allow_html=True)
            except Exception as e:
                st.error(f"Nmap error: {e}")
    st.markdown('</div>', unsafe_allow_html=True)

# -- YARA PANEL --
elif tool == "YARA Scanner":
    st.markdown('<div class="card">', unsafe_allow_html=True)
    st.subheader("🦠 YARA Rule Builder & File Scanner")
    yara_templates = {
        "Suspicious String": '''rule suspicious_string_rule
{
    meta:
        description = "Detects suspicious string in files"
        author = "Voxelta Security Toolkit"
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
        author = "Voxelta Security Toolkit"
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
        height=220, key="yara_rule_box"
    )

    col1, col2 = st.columns(2)
    with col1:
        if st.button("🛡️ Validate Rule"):
            try:
                yara.compile(source=rule_content)
                st.success("YARA rule compiled successfully")
            except Exception as e:
                st.error(f"YARA syntax error: {str(e)}")
        if st.session_state["gemini"]:
            if st.button("💡 Gemini: Explain Rule"):
                with st.spinner("Gemini is analyzing..."):
                    explain = st.session_state["gemini"].analyze(
                        rule_content, "Explain this YARA rule for malware analysts."
                    )
                st.markdown(f'<div class="ai-explain"><b>Gemini Explanation:</b><br>{explain}</div>', unsafe_allow_html=True)
    with col2:
        files = st.file_uploader(
            "Upload files to scan", type=['exe', 'dll', 'pdf', 'doc', 'txt'],
            accept_multiple_files=True
        )
        if files and rule_content:
            if st.button("🔎 Scan Files"):
                for uploaded_file in files:
                    with tempfile.NamedTemporaryFile(delete=False) as tmp_file:
                        tmp_file.write(uploaded_file.read())
                        tmp_path = tmp_file.name
                    try:
                        rules = yara.compile(source=rule_content)
                        matches = rules.match(tmp_path, timeout=30)
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
                    except Exception as e:
                        st.error(f"Scan failed for `{uploaded_file.name}`: {str(e)}")
                    finally:
                        os.unlink(tmp_path)
    st.markdown('</div>', unsafe_allow_html=True)

# -- Footer --
st.markdown("""
    <hr style="margin-top:2.2em;margin-bottom:0;">
    <div style='text-align: center; color: #666; font-size: 1em;'>
        Made with ❤️ by <b>Voxelta Private Limited</b>.<br>
        <a href='https://www.linkedin.com/in/dinesh-k-3199ab1b0/' target='_blank'>Dinesh K on LinkedIn</a>
    </div>
""", unsafe_allow_html=True)
