import streamlit as st
import nmap, socket, ssl, requests, yara, dns.resolver, whois, tempfile, os
from datetime import datetime
import google.generativeai as genai

# --- Branding & Header ---
st.set_page_config(page_title="CyberSec Assistant – Voxelta", page_icon="🛡️", layout="wide")
st.markdown("""
    <div style="background: linear-gradient(90deg, #1e3c72 0%, #2a5298 100%);
    padding:1.1rem 2rem 1.3rem 2rem; border-radius:10px;margin-bottom:2rem;box-shadow:0 4px 18px #1e3c7236;">
        <h2 style="color:#fff;margin:0;">🛡️ CyberSec Assistant <span style="font-size:0.7em; font-weight:normal;">(by Voxelta Private Limited)</span></h2>
        <div style="color:#ffe057;margin-top:6px;">
            <b>For Security Pros, Students & Auditors</b> — 
            <a style="color:#ffe057;" href="https://www.linkedin.com/in/dinesh-k-3199ab1b0/" target="_blank">Dinesh K</a>
        </div>
        <p style="color:#e0e0e0;margin:0;font-size:1.08em;">Python & Gemini AI Security Suite — Fast, Safe, Cloud-Friendly.</p>
    </div>
""", unsafe_allow_html=True)
st.markdown("""
    <div style="background:#fff3cd;padding:1rem 1.2rem;border:1px solid #ffeaa7;border-radius:8px;font-size:1em;">
        <b>⚠️ For authorized security research & learning only!</b> Never scan/test targets without permission.
    </div>
""", unsafe_allow_html=True)
st.write("")

# --- Gemini Setup ---
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

if "bot" not in st.session_state: st.session_state["bot"] = None
if "history" not in st.session_state: st.session_state["history"] = []

# --- Sidebar ---
with st.sidebar:
    st.header("🔑 Gemini AI Key")
    gkey = st.text_input("Gemini API Key", type="password")
    if gkey and not st.session_state["bot"]:
        st.session_state["bot"] = CyberBot()
        if st.session_state["bot"].init_gemini(gkey): st.success("Gemini Ready.")
    bot = st.session_state["bot"] or CyberBot()

# --- Main Tabs ---
tab1, tab2, tab3, tab4, tab5 = st.tabs(
    ["🔍 Nmap Scanner", "🌐 DNS & WHOIS", "📡 HTTP(S) Analyzer", "📝 YARA Builder", "💬 Gemini Chat"]
)

# --- 1. Nmap Scanner (python-nmap) ---
with tab1:
    st.markdown("### 🔍 Python Nmap Scanner")
    target = st.text_input("Target IP/Domain", value="scanme.nmap.org", key="nmap_target")
    port_range = st.text_input("Ports (e.g., 22-443 or 80,443,8080)", value="22-80", key="nmap_ports")
    scan_btn = st.button("Run Nmap Scan", key="nmap_run")
    if scan_btn and target:
        nm = nmap.PortScanner()
        with st.spinner("Scanning..."):
            try:
                nm.scan(target, port_range)
                out = ""
                for host in nm.all_hosts():
                    out += f"\n**Host:** {host} ({nm[host].hostname()})\nState: {nm[host].state()}\n"
                    for proto in nm[host].all_protocols():
                        lport = nm[host][proto].keys()
                        for port in lport:
                            state = nm[host][proto][port]['state']
                            svc = nm[host][proto][port].get('name', '')
                            out += f"Port: {port}\tState: {state}\tService: {svc}\n"
                st.code(out or "No open ports found.", language="text")
                st.session_state["history"].append({"type": "nmap", "target": target, "result": out, "when": datetime.now().isoformat()})
                if bot.genai_client and st.toggle("AI Analyze", key="nmap_ai"):
                    st.success(bot.ai("Explain this nmap output:\n" + out))
            except Exception as e:
                st.error(f"Nmap error: {e}")

# --- 2. DNS & WHOIS ---
with tab2:
    st.markdown("### 🌐 DNS & WHOIS Lookup")
    dns_domain = st.text_input("Domain", value="scanme.nmap.org", key="dns_domain")
    if st.button("Lookup DNS & WHOIS", key="dns_btn") and dns_domain:
        # DNS
        try:
            answers = dns.resolver.resolve(dns_domain, "A")
            st.write("**A Records:**", [a.address for a in answers])
        except Exception as e:
            st.warning(f"DNS A error: {e}")
        try:
            mx = dns.resolver.resolve(dns_domain, "MX")
            st.write("**MX Records:**", [str(r.exchange) for r in mx])
        except Exception as e:
            st.info(f"No MX record or error: {e}")
        # WHOIS
        try:
            w = whois.whois(dns_domain)
            st.write("**WHOIS Name:**", w.name)
            st.write("**WHOIS Org:**", w.org)
            st.write("**WHOIS Emails:**", w.emails)
        except Exception as e:
            st.warning(f"WHOIS error: {e}")
        if bot.genai_client and st.toggle("AI Analyze DNS/WHOIS", key="dns_ai"):
            summary = f"A: {[a.address for a in answers]}\nMX: {[str(r.exchange) for r in mx]}\nWhois: {w.text if 'w' in locals() else ''}"
            st.success(bot.ai("Explain this DNS/WHOIS data:\n" + summary))

# --- 3. HTTP/HTTPS Analyzer ---
with tab3:
    st.markdown("### 📡 HTTP(S) Analyzer")
    url = st.text_input("URL (http[s]://...)", value="http://scanme.nmap.org", key="http_url")
    if st.button("Analyze URL", key="http_btn") and url:
        try:
            r = requests.get(url, timeout=10)
            st.write("**Status Code:**", r.status_code)
            st.write("**Headers:**")
            st.json(dict(r.headers))
            try:
                if url.startswith("https"):
                    cert = ssl.get_server_certificate((r.url.split('/')[2], 443))
                    st.text_area("SSL Certificate", cert, height=120)
            except Exception as e:
                st.info(f"SSL cert fetch error: {e}")
            st.session_state["history"].append({"type": "http", "url": url, "result": dict(r.headers), "when": datetime.now().isoformat()})
            if bot.genai_client and st.toggle("AI Analyze HTTP", key="http_ai"):
                st.success(bot.ai(f"Analyze these HTTP headers and server info:\n{dict(r.headers)}"))
        except Exception as e:
            st.error(f"HTTP(s) error: {e}")

# --- 4. YARA Builder/Scanner ---
with tab4:
    st.markdown("### 📝 YARA Rule Builder & File Scanner")
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

# --- 5. Gemini AI Chat Assistant ---
with tab5:
    st.markdown("### 💬 Gemini AI Security Assistant")
    if 'messages' not in st.session_state:
        st.session_state.messages = []
    for message in st.session_state.messages:
        with st.chat_message(message["role"]):
            st.markdown(message["content"])
    if prompt := st.chat_input("Ask about cybersecurity, results, or tools..."):
        st.session_state.messages.append({"role": "user", "content": prompt})
        with st.chat_message("user"):
            st.markdown(prompt)
        with st.chat_message("assistant"):
            with st.spinner("AI is thinking..."):
                resp = bot.ai(prompt)
                st.markdown(resp)
                st.session_state.messages.append({"role": "assistant", "content": resp})

# --- Export scan history ---
st.markdown("---")
if st.session_state["history"]:
    st.markdown("#### 📚 Session Scan History & Export")
    idx = st.selectbox("View Previous", options=list(range(len(st.session_state["history"]))),
        format_func=lambda i: f"{st.session_state['history'][i]['type'].upper()} - {st.session_state['history'][i]['when']}")
    item = st.session_state["history"][idx]
    st.write(f"**Type:** {item['type']}  \n**Target:** {item.get('target', item.get('url',''))}")
    st.code(str(item['result']))
    st.download_button("Download Result (.txt)", str(item['result']), file_name=f"scan_{item['type']}_{item['when']}.txt")

st.markdown("---")
st.markdown("""
    <div style='text-align: center; color: #666; font-size: 0.98em;'>
        Made with ❤️ by <b>Voxelta Private Limited</b>.<br>
        <a href='https://www.linkedin.com/in/dinesh-k-3199ab1b0/' target='_blank'>Dinesh K on LinkedIn</a>
    </div>
""", unsafe_allow_html=True)
