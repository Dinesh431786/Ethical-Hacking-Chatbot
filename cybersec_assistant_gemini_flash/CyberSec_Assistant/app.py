import streamlit as st
import nmap
from datetime import datetime
import google.generativeai as genai
import re

# ========== Branding & Header ==========
st.set_page_config(page_title="Nmap Pro Suite – Voxelta", page_icon="🛡️", layout="wide")
st.markdown("""
<style>
.big-brand {
    background: linear-gradient(90deg,#1e3c72 0%,#2a5298 100%);
    padding:1.4rem 2rem 1.2rem 2rem;
    border-radius:13px;
    margin-bottom:1.3rem;
    box-shadow:0 4px 18px #2233633c;
}
.big-brand h2 {color:#fff;margin-bottom:0;}
.big-brand .sub {color:#ffe057;font-weight:bold;}
.big-brand .link {color:#ffe057;}
.stTabs [data-baseweb="tab-list"] {justify-content: flex-start;}
.card {
    background:#f6f8fa;
    border-radius:11px;
    box-shadow:0 2px 12px #cdd0e033;
    padding:1.1em 1.7em 1em 1.7em;
    margin-bottom:2.1rem;
    border:1.5px solid #e2e5ec;
}
.scan-header {
    color:#1e3c72;font-size:1.16em;font-weight:700;margin-bottom:0.7em;
}
.scan-hint {color:#6072b7;font-size:1em;font-style:italic;margin-bottom:0.5em;}
.copy-btn {float:right;margin-left:12px;font-size:1em;}
.errbox {
    background: #fff3cd;
    border: 1px solid #ffeaa7;
    padding: 1rem;
    border-radius: 8px;
    margin: 1rem 0;
    color: #665c00;
    font-size: 1.1em;
}
</style>
<div class="big-brand">
  <h2>🛡️ Nmap Pro Suite <span style="font-size:0.7em;font-weight:normal;">by Voxelta</span></h2>
  <div class="sub">
      The Ultimate Python & Gemini AI Security Scanner Suite &ndash; for Cyber Security Pros, Students, Red Teams
      &nbsp;|&nbsp;
      <a class="link" href="https://www.linkedin.com/in/dinesh-k-3199ab1b0/" target="_blank">Dinesh K</a>
  </div>
</div>
""", unsafe_allow_html=True)

# ========== Gemini Helper ==========
class GeminiBot:
    """Gemini API client for AI analysis."""
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
        if not self.client:
            return "Gemini API not initialized."
        try:
            if prompt:
                return self.client.generate_content(f"{prompt}\n\n{text}").text
            return self.client.generate_content(text).text
        except Exception as e:
            return f"AI Error: {e}"

if "gemini" not in st.session_state: st.session_state["gemini"] = None
if "gemini_init" not in st.session_state: st.session_state["gemini_init"] = False

# ========== Sidebar: Gemini, Scan Profiles ==========
with st.sidebar:
    st.header("🔑 Gemini AI")
    gkey = st.text_input("Gemini API Key", type="password", help="Paste your Gemini API key here.")
    if gkey and not st.session_state["gemini_init"]:
        st.session_state["gemini"] = GeminiBot()
        if st.session_state["gemini"].init(gkey):
            st.success("Gemini API Connected!")
            st.session_state["gemini_init"] = True

    st.write("---")
    st.markdown("""
    **Scan Profiles**  
    Save frequently used arguments as scan "profiles" for one-click advanced usage.
    """)
    if "profiles" not in st.session_state:
        st.session_state["profiles"] = {"Fast Top 1000": "-T4 -F", "All TCP": "-p- -T4"}
    if st.button("Save current custom args as new profile", key="save_profile"):
        prof_name = st.text_input("Profile Name", key="prof_name_save")
        prof_val = st.session_state.get("custom_args", "-sS")
        if prof_name:
            st.session_state["profiles"][prof_name] = prof_val
            st.success(f"Profile '{prof_name}' saved.")
    if len(st.session_state["profiles"]) > 0:
        st.markdown("**Load Profile:**")
        chosen_prof = st.selectbox(
            "Profiles", list(st.session_state["profiles"].keys()), key="prof_sel"
        )
        if st.button("Use Profile", key="use_prof"):
            st.session_state["custom_args"] = st.session_state["profiles"][chosen_prof]
            st.success(f"Loaded: {chosen_prof}")

    st.write("---")
    st.markdown("""
    <span style="color:#4a5f88;font-size:0.97em;">
    <b>Instructions:</b><br>
    - Pick a tab (scan type)<br>
    - Fill in target and scan options<br>
    - Run and (optionally) analyze with Gemini AI.<br>
    <b>All output is real, advanced, and professional – for authorized security testing only.</b>
    </span>
    """, unsafe_allow_html=True)

# ========== Main Area: Tabs for Advanced Nmap Scans ==========
tab_titles = [
    "🌐 Host Discovery", "🔢 Port Scan", "🕵️ Service Version", "🤖 OS Detection", "⚡ Aggressive",
    "🧬 Vuln Scripts", "⏱️ Timing/Tuning", "🛠️ Custom"
]
tabs = st.tabs(tab_titles)

# ---- Shared Scan Helper ----
def run_nmap(target, arguments):
    """Run a nmap scan, return raw CSV output."""
    nm = nmap.PortScanner()
    try:
        scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        nm.scan(target, arguments=arguments)
        out = nm.csv()
        if not out.strip():
            return f"No results. The host may be down, protected, or unreachable. Time: {scan_time}"
        return out
    except Exception as e:
        return f"Error: {str(e)}\nCheck your input, arguments, and target accessibility."

def show_scan_results(output, label="Output", advanced=False):
    """Show results in a code card, add download, and optional AI analysis."""
    st.markdown(f"<div class='scan-header'>{label}</div>", unsafe_allow_html=True)
    st.code(output, language="text")
    st.download_button("⬇️ Download Result (.txt)", output, file_name=f"nmap_result_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
    if st.session_state["gemini"] and st.toggle("🔎 Gemini AI Analysis", value=False, help="Let Gemini analyze and explain the scan output."):
        prompt = "As a security expert, analyze and summarize this Nmap output. Give risk and security insights."
        st.success(st.session_state["gemini"].analyze(output, prompt=prompt))
    if advanced:
        st.markdown("<span style='color:#888;'>Raw result (CSV): Easily parsable for custom reporting, SIEM, or further tool integration.</span>", unsafe_allow_html=True)

# 1. Host Discovery Tab
with tabs[0]:
    st.markdown(
        '<div class="card">Ping all hosts on a subnet (no port scan). Use for live host discovery in networks.<br>'
        '<span class="scan-hint">Equivalent: <code>nmap -sn target</code></span></div>',
        unsafe_allow_html=True)
    target = st.text_input("Target IP/Subnet", value="192.168.1.0/24", key="t_ping")
    if st.button("Run Host Discovery", key="run_ping"):
        output = run_nmap(target, "-sn")
        show_scan_results(output, "Host Discovery (Ping Scan)")

# 2. Port Scan Tab
with tabs[1]:
    st.markdown(
        '<div class="card">Scan top 1000 TCP ports quickly for open/filtered/closed ports.<br>'
        '<span class="scan-hint">Equivalent: <code>nmap -T4 -F target</code></span></div>',
        unsafe_allow_html=True)
    target = st.text_input("Target IP/Domain", value="scanme.nmap.org", key="t_port")
    if st.button("Run Port Scan", key="run_port"):
        output = run_nmap(target, "-T4 -F")
        show_scan_results(output, "Fast Port Scan")

# 3. Service Version Tab
with tabs[2]:
    st.markdown(
        '<div class="card">Detect service/software names and versions on open ports.<br>'
        '<span class="scan-hint">Equivalent: <code>nmap -sV target</code></span></div>',
        unsafe_allow_html=True)
    target = st.text_input("Target", value="scanme.nmap.org", key="t_svc")
    if st.button("Run Service Detection", key="run_svc"):
        output = run_nmap(target, "-sV")
        show_scan_results(output, "Service & Version Detection")

# 4. OS Detection Tab
with tabs[3]:
    st.markdown(
        '<div class="card">Try to identify the OS/Kernel of remote hosts (TCP/IP stack fingerprinting).<br>'
        '<span class="scan-hint">Equivalent: <code>nmap -O target</code></span></div>',
        unsafe_allow_html=True)
    target = st.text_input("Target", value="scanme.nmap.org", key="t_os")
    if st.button("Run OS Detection", key="run_os"):
        output = run_nmap(target, "-O")
        show_scan_results(output, "OS Detection")

# 5. Aggressive Scan Tab
with tabs[4]:
    st.markdown(
        '<div class="card">All-in-one: runs OS/service detection, script scan, traceroute, and more. Noisy!<br>'
        '<span class="scan-hint">Equivalent: <code>nmap -A target</code></span></div>',
        unsafe_allow_html=True)
    target = st.text_input("Target", value="scanme.nmap.org", key="t_agg")
    if st.button("Run Aggressive Scan", key="run_agg"):
        output = run_nmap(target, "-A")
        show_scan_results(output, "Aggressive Full Scan", advanced=True)

# 6. Vuln Scripts Tab
with tabs[5]:
    st.markdown(
        '<div class="card">Run all default NSE scripts for CVEs, known vulns, misconfigs, and exploits.<br>'
        '<span class="scan-hint">Equivalent: <code>nmap --script vuln target</code></span></div>',
        unsafe_allow_html=True)
    target = st.text_input("Target", value="scanme.nmap.org", key="t_vuln")
    if st.button("Run Vulnerability Scan", key="run_vuln"):
        output = run_nmap(target, "--script vuln")
        show_scan_results(output, "Vuln Scripts")

# 7. Timing/Tuning Tab
with tabs[6]:
    st.markdown(
        '<div class="card">Fine-tune scan timing, host rate, retries, parallelism, and evasion for IDS/WAF testing.<br>'
        '<span class="scan-hint">Examples: <code>-T2 --max-retries 1 --scan-delay 50ms</code></span></div>',
        unsafe_allow_html=True)
    target = st.text_input("Target", value="scanme.nmap.org", key="t_tune")
    timing_args = st.text_input("Timing/Tuning Args", value="-T2 --max-retries 1 --scan-delay 50ms", key="timing_args")
    if st.button("Run Timing/Tuning Scan", key="run_tune"):
        output = run_nmap(target, timing_args)
        show_scan_results(output, f"Timing/Tuning ({timing_args})")

# 8. Custom Tab
with tabs[7]:
    st.markdown(
        '<div class="card">Full Nmap CLI argument control for advanced users. Any args/scripts.<br>'
        '<span class="scan-hint">Example: <code>-sS -p 21,22,80 --script=http-enum</code></span></div>',
        unsafe_allow_html=True)
    target = st.text_input("Target", value="scanme.nmap.org", key="t_custom")
    custom_args = st.text_input("Custom Nmap Arguments", value="-sS -p 80,443", key="custom_args")
    if st.button("Run Custom Scan", key="run_custom"):
        output = run_nmap(target, custom_args)
        show_scan_results(output, f"Custom Scan ({custom_args})", advanced=True)

# ========== Footer Branding ==========
st.markdown("""
<hr style="margin-top:2.3em;margin-bottom:0;">
<div style='text-align: center; color: #666; font-size: 1em;'>
    Made with ❤️ by <b>Voxelta Private Limited</b>.<br>
    <a href='https://www.linkedin.com/in/dinesh-k-3199ab1b0/' target='_blank'>Dinesh K on LinkedIn</a>
</div>
""", unsafe_allow_html=True)
