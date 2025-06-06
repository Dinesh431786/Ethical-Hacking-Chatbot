import streamlit as st
import nmap
import yara
import tempfile
import os
import google.generativeai as genai
from datetime import datetime

# Branding/Header
st.set_page_config(page_title="Voxelta Security Toolkit", page_icon="🛡️", layout="centered")
st.markdown("""
<div style="background: linear-gradient(90deg,#1e3c72 0%,#2a5298 100%);
padding:1.2rem 2rem 1.1rem 2rem; border-radius:13px; margin-bottom:1.2rem;">
  <h2 style="color:#fff;margin-bottom:0;">🛡️ Voxelta Security Toolkit</h2>
  <div style="color:#ffe057;">For Ethical Hackers & Researchers |
    <a style="color:#ffe057;" href="https://www.linkedin.com/in/dinesh-k-3199ab1b0/" target="_blank">Dinesh K</a>
  </div>
</div>
""", unsafe_allow_html=True)

# Gemini Helper
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

# Sidebar: Tool Selector & Gemini
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

# =========== NMAP PANEL ===========
if tool == "Nmap Scanner":
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
    if st.button("Run Nmap Scan"):
        if not target:
            st.error("Please enter a target!")
        else:
            args = scan_types[scan]
            if ports and scan in ["Port Scan", "Stealth"]:
                args += f" -p {ports}"
            st.info(f"Running: nmap {args} {target}")
            nm = nmap.PortScanner()
            try:
                nm.scan(target, arguments=args)
                result = nm.csv()
                st.code(result or "No results.", language="text")
                if st.session_state["gemini"] and st.toggle("Gemini AI Analysis", key="nmap_ai"):
                    prompt = f"Explain this Nmap {scan} scan result for a cyber security expert."
                    st.success(st.session_state["gemini"].analyze(result, prompt=prompt))
                st.download_button("⬇️ Download Result (.txt)", result, file_name=f"nmap_{scan}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
            except Exception as e:
                st.error(f"Nmap error: {e}")

# =========== YARA PANEL ===========
elif tool == "YARA Scanner":
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
        if st.button("💡 Explain with Gemini"):
            if st.session_state["gemini"]:
                st.markdown(st.session_state["gemini"].analyze(
                    rule_content, "Explain this YARA rule for malware analysts."
                ))
            else:
                st.warning("Configure Gemini API first.")
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

# ============= FOOTER =============
st.markdown("""
    <hr style="margin-top:2.2em;margin-bottom:0;">
    <div style='text-align: center; color: #666; font-size: 1em;'>
        Made with ❤️ by <b>Voxelta Private Limited</b>.<br>
        <a href='https://www.linkedin.com/in/dinesh-k-3199ab1b0/' target='_blank'>Dinesh K on LinkedIn</a>
    </div>
""", unsafe_allow_html=True)
