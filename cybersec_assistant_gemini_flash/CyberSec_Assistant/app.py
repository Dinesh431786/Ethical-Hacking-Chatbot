import streamlit as st
import nmap
import google.generativeai as genai

# ---------- UI/UX Styles & Branding ----------
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
.box {
    background:#f6f8fa;
    border-radius:11px;
    box-shadow:0 2px 9px #cdd0e033;
    padding:1.1em 1.7em 1em 1.7em;
    margin-bottom:2rem;
}
.stTabs [data-baseweb="tab-list"] {justify-content: flex-start;}
.run-btn {font-size:1.1em;background:#2a5298;color:#fff;padding:0.6em 2.2em;
    border-radius:7px;margin-top:1.1em;font-weight:600;}
.run-btn:hover {background:#223363;}
</style>
<div class="big-brand">
  <h2>🛡️ Nmap Pro Suite <span style="font-size:0.7em;font-weight:normal;">by Voxelta</span></h2>
  <div class="sub">
      The Ultimate Python & Gemini AI Security Scanner Suite – for Cyber Security Pros & Students
      &nbsp;|&nbsp;
      <a class="link" href="https://www.linkedin.com/in/dinesh-k-3199ab1b0/" target="_blank">Dinesh K</a>
  </div>
</div>
""", unsafe_allow_html=True)

# ---------- Gemini Helper ----------
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
    def analyze(self, text):
        if not self.client: return ""
        try: return self.client.generate_content(text).text
        except Exception as e: return f"AI Error: {e}"

if "gemini" not in st.session_state: st.session_state["gemini"] = None
if "gemini_init" not in st.session_state: st.session_state["gemini_init"] = False

# ---------- Sidebar: Gemini + Scan Params ----------
with st.sidebar:
    st.header("⚙️ Configure & Authenticate")
    gkey = st.text_input("Gemini API Key", type="password", help="Paste your Gemini API key here")
    if gkey and not st.session_state["gemini_init"]:
        st.session_state["gemini"] = GeminiBot()
        if st.session_state["gemini"].init(gkey):
            st.success("Gemini API Connected!")
            st.session_state["gemini_init"] = True
    st.write("---")
    st.markdown("""
    <span style="color:#4a5f88;font-size:0.97em;">
    <b>Instructions:</b>
    - Choose your scan type
    - Enter your target and options
    - Run and analyze with Gemini AI if needed<br>
    <br>
    <b>All output is real, advanced, and professional – for authorized security testing only.</b>
    </span>
    """, unsafe_allow_html=True)

# ---------- Tabbed Main UI: All Pro Nmap Scans ----------
tabs = [
    "Host Discovery", "Port Scan", "Service Version", "OS Detection", "Aggressive Scan", "Vuln Scripts", "Custom"
]
tab_icons = ["🌐","🔢","🕵️‍♂️","🤖","⚡","🧬","🛠️"]
chosen, = st.tabs([f"{icon} {name}" for icon,name in zip(tab_icons,tabs)])

# --- Shared Scan Helper ---
def run_nmap(target, args):
    nm = nmap.PortScanner()
    try:
        nm.scan(target, arguments=args)
        return nm.csv()
    except Exception as e:
        return f"Nmap error: {e}"

# ---- 1. Host Discovery ----
with chosen if chosen.title().startswith("🌐") else st.container():
    st.markdown('<div class="box"><b>Host Discovery ("Ping Scan")</b><br>'
                'Find live hosts on a subnet or list. No port scan. <br>'
                'Equivalent to: <code>nmap -sn target</code></div>', unsafe_allow_html=True)
    target = st.text_input("Target IP/Subnet (e.g. 192.168.1.0/24, site.com)", key="ping_tgt")
    if st.button("Run Host Discovery", key="run_ping", help="Ping all hosts, no port scan", use_container_width=True):
        output = run_nmap(target, "-sn")
        st.code(output, language="text")
        if st.session_state["gemini"] and st.toggle("Gemini AI Analysis", key="g_ping"):
            st.success(st.session_state["gemini"].analyze("Explain this Nmap host discovery output:\n" + output))

# ---- 2. Port Scan ----
with chosen if chosen.title().startswith("🔢") else st.container():
    st.markdown('<div class="box"><b>TCP Port Scan</b><br>'
                'Scan top 1000 TCP ports on target(s). <br>'
                'Equivalent: <code>nmap -T4 -F target</code></div>', unsafe_allow_html=True)
    target = st.text_input("Target IP/Domain", key="port_tgt")
    if st.button("Run Port Scan", key="run_port", use_container_width=True):
        output = run_nmap(target, "-T4 -F")
        st.code(output, language="text")
        if st.session_state["gemini"] and st.toggle("Gemini AI Analysis", key="g_port"):
            st.success(st.session_state["gemini"].analyze("Explain this Nmap port scan output:\n" + output))

# ---- 3. Service Version ----
with chosen if chosen.title().startswith("🕵️") else st.container():
    st.markdown('<div class="box"><b>Service & Version Detection</b><br>'
                'Detect services and versions running on ports.<br>'
                'Equivalent: <code>nmap -sV target</code></div>', unsafe_allow_html=True)
    target = st.text_input("Target IP/Domain", key="svc_tgt")
    if st.button("Run Service Version Scan", key="run_svc", use_container_width=True):
        output = run_nmap(target, "-sV")
        st.code(output, language="text")
        if st.session_state["gemini"] and st.toggle("Gemini AI Analysis", key="g_svc"):
            st.success(st.session_state["gemini"].analyze("Explain this Nmap service/version scan:\n" + output))

# ---- 4. OS Detection ----
with chosen if chosen.title().startswith("🤖") else st.container():
    st.markdown('<div class="box"><b>OS Detection</b><br>'
                'Try to determine the remote OS.<br>'
                'Equivalent: <code>nmap -O target</code></div>', unsafe_allow_html=True)
    target = st.text_input("Target IP/Domain", key="os_tgt")
    if st.button("Run OS Detection", key="run_os", use_container_width=True):
        output = run_nmap(target, "-O")
        st.code(output, language="text")
        if st.session_state["gemini"] and st.toggle("Gemini AI Analysis", key="g_os"):
            st.success(st.session_state["gemini"].analyze("Explain this Nmap OS detection scan:\n" + output))

# ---- 5. Aggressive Scan ----
with chosen if chosen.title().startswith("⚡") else st.container():
    st.markdown('<div class="box"><b>Aggressive Full Scan</b><br>'
                'All probes: service/version, OS, traceroute, scripts.<br>'
                'Equivalent: <code>nmap -A target</code></div>', unsafe_allow_html=True)
    target = st.text_input("Target IP/Domain", key="agg_tgt")
    if st.button("Run Aggressive Scan", key="run_agg", use_container_width=True):
        output = run_nmap(target, "-A")
        st.code(output, language="text")
        if st.session_state["gemini"] and st.toggle("Gemini AI Analysis", key="g_agg"):
            st.success(st.session_state["gemini"].analyze("Explain this Nmap aggressive scan:\n" + output))

# ---- 6. Vuln Scripts ----
with chosen if chosen.title().startswith("🧬") else st.container():
    st.markdown('<div class="box"><b>Vulnerability Script Scan</b><br>'
                'Run all default Nmap vuln NSE scripts.<br>'
                'Equivalent: <code>nmap --script vuln target</code></div>', unsafe_allow_html=True)
    target = st.text_input("Target IP/Domain", key="vuln_tgt")
    if st.button("Run Vuln Script Scan", key="run_vuln", use_container_width=True):
        output = run_nmap(target, "--script vuln")
        st.code(output, language="text")
        if st.session_state["gemini"] and st.toggle("Gemini AI Analysis", key="g_vuln"):
            st.success(st.session_state["gemini"].analyze("Explain this Nmap vuln script scan:\n" + output))

# ---- 7. Custom Scan ----
with chosen if chosen.title().startswith("🛠️") else st.container():
    st.markdown('<div class="box"><b>Custom Nmap Arguments</b><br>'
                'Enter any Nmap CLI args.<br>'
                'Example: <code>-sS -p 21,22,80 --script=http-enum</code></div>', unsafe_allow_html=True)
    target = st.text_input("Target (IP/Domain)", key="custom_tgt")
    custom_args = st.text_input("Custom Nmap Args", value="-sS -p 80,443", key="custom_args")
    if st.button("Run Custom Nmap", key="run_custom", use_container_width=True):
        output = run_nmap(target, custom_args)
        st.code(output, language="text")
        if st.session_state["gemini"] and st.toggle("Gemini AI Analysis", key="g_custom"):
            st.success(st.session_state["gemini"].analyze("Explain this Nmap custom scan:\n" + output))

# ---------- Footer ----------
st.markdown("""
<hr style="margin-top:2em;margin-bottom:0;">
<div style='text-align: center; color: #666; font-size: 1em;'>
    Made with ❤️ by <b>Voxelta Private Limited</b>.<br>
    <a href='https://www.linkedin.com/in/dinesh-k-3199ab1b0/' target='_blank'>Dinesh K on LinkedIn</a>
</div>
""", unsafe_allow_html=True)
