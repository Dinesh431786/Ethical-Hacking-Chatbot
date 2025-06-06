import streamlit as st
import nmap, socket, ssl, requests, yara, dns.resolver, whois, tempfile, os
from datetime import datetime
import google.generativeai as genai

# ---- Branding ----
st.set_page_config(page_title="CyberSec Assistant – Voxelta", page_icon="🛡️", layout="wide")
st.markdown("""
    <div style="background: linear-gradient(90deg, #1e3c72 0%, #2a5298 100%);
        padding:1.1rem 2rem 1.3rem 2rem; border-radius:12px 12px 0 0;
        margin-bottom:0.6rem;box-shadow:0 4px 18px #1e3c7244;">
        <h2 style="color:#fff;margin:0;">🛡️ CyberSec Assistant <span style="font-size:0.8em; font-weight:normal;">by Voxelta</span></h2>
        <div style="color:#ffe057;margin-top:4px;">
            <b>For Security Pros, Students & Auditors</b>
        </div>
        <div style="color:#f3f3f3;">AI-Powered Security Toolkit &nbsp;|&nbsp;
        <a style="color:#ffe057;text-decoration:underline;" href="https://www.linkedin.com/in/dinesh-k-3199ab1b0/" target="_blank">Dinesh K</a>
        </div>
    </div>
""", unsafe_allow_html=True)
st.markdown("""
    <div style="background:#fff9e3;padding:0.9rem 1.3rem;border:1.5px solid #ffeaa7;border-radius:0 0 12px 12px;margin-bottom:1rem;font-size:1em;">
        <b>⚠️ Ethical Use Only!</b> Always get permission before testing/scanning real systems.
    </div>
""", unsafe_allow_html=True)

# ---- Gemini Setup & Helper ----
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

# ---- Sidebar ----
with st.sidebar:
    st.header("🔑 Gemini AI")
    gkey = st.text_input("Gemini API Key", type="password", help="Paste your Gemini API key")
    if gkey and not st.session_state["bot"]:
        st.session_state["bot"] = CyberBot()
        if st.session_state["bot"].init_gemini(gkey): st.success("Gemini Ready.")
    bot = st.session_state["bot"] or CyberBot()
    st.markdown("---")
    st.markdown("#### 🛠️ Quick Links")
    st.markdown("""
        - [Voxelta](https://voxelta.com)  
        - [LinkedIn](https://www.linkedin.com/in/dinesh-k-3199ab1b0/)  
        - [Gemini API Key](https://aistudio.google.com/app/apikey)  
    """)
    st.markdown("---")
    st.markdown("**Pro Tip:** Results and scan history are below each tool.")

# ---- Dashboard / Landing ----
with st.expander("🏠 Quick Start & Features", expanded=True):
    st.markdown("""
        - **Nmap (Python):** Scan ports/services safely on any host/IP.
        - **DNS & WHOIS:** Lookup domains, MX records, emails.
        - **HTTP(S) Analyzer:** Get headers, SSL cert, server info.
        - **YARA:** Build, validate, and scan files for malware patterns.
        - **Gemini AI:** Explain results, analyze output, answer questions.
        - **History:** View and export all session scans.
        ---
        <span style="color:#2583c4;font-size:1.1em;">Everything is cloud-ready, safe, and requires only Python packages!</span>
    """, unsafe_allow_html=True)

# ---- Tool Tabs ----
tab1, tab2, tab3, tab4, tab5 = st.tabs(
    ["🔍 Nmap Scanner", "🌐 DNS & WHOIS", "📡 HTTP(S) Analyzer", "📝 YARA", "💬 Gemini Chat"]
)

with tab1:
    st.markdown("#### <span style='color:#2a5298;'>Nmap Port & Service Scanner</span>", unsafe_allow_html=True)
    target = st.text_input("Target (IP/Domain)", value="scanme.nmap.org", key="nmap_target")
    port_range = st.text_input("Ports", value="22-80", key="nmap_ports")
    scan_btn = st.button("🚦 Start Nmap Scan", key="nmap_run")
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
                card = st.container()
                with card:
                    st.code(out or "No open ports found.", language="text")
                    if bot.genai_client and st.toggle("🧠 AI Analyze", key="nmap_ai"):
                        st.success(bot.ai("Explain this nmap output:\n" + out))
                st.session_state["history"].append({"type": "nmap", "target": target, "result": out, "when": datetime.now().isoformat()})
            except Exception as e:
                st.error(f"Nmap error: {e}")

with tab2:
    st.markdown("#### <span style='color:#2a5298;'>DNS & WHOIS Lookup</span>", unsafe_allow_html=True)
    dns_domain = st.text_input("Domain", value="scanme.nmap.org", key="dns_domain")
    if st.button("🔍 DNS & WHOIS", key="dns_btn") and dns_domain:
        try:
            answers = dns.resolver.resolve(dns_domain, "A")
            st.success(f"**A Records:** {', '.join([a.address for a in answers])}")
        except Exception as e:
            st.warning(f"DNS A error: {e}")
        try:
            mx = dns.resolver.resolve(dns_domain, "MX")
            st.info(f"**MX Records:** {', '.join([str(r.exchange) for r in mx])}")
        except Exception as e:
            st.info(f"No MX record or error: {e}")
        try:
            w = whois.whois(dns_domain)
            st.info(f"**WHOIS Name:** {w.name} \n**Org:** {w.org} \n**Emails:** {w.emails}")
        except Exception as e:
            st.warning(f"WHOIS error: {e}")
        if bot.genai_client and st.toggle("AI Analyze DNS/WHOIS", key="dns_ai"):
            summary = f"A: {[a.address for a in answers]}\nMX: {[str(r.exchange) for r in mx]}\nWhois: {w.text if 'w' in locals() else ''}"
            st.success(bot.ai("Explain this DNS/WHOIS data:\n" + summary))

with tab3:
    st.markdown("#### <span style='color:#2a5298;'>HTTP(S) Analyzer</span>", unsafe_allow_html=True)
    url = st.text_input("URL (http[s]://...)", value="http://scanme.nmap.org", key="http_url")
    if st.button("🔬 Analyze URL", key="http_btn") and url:
        try:
            r = requests.get(url, timeout=10)
            st.success(f"**Status Code:** {r.status_code}")
            st.write("**Headers:**")
            st.json(dict(r.headers))
            try:
                if url.startswith("https"):
                    cert = ssl.get_server_certificate((r.url.split('/')[2], 443))
                    st.text_area("SSL Certificate", cert, height=100)
            except Exception as e:
                st.info(f"SSL cert fetch error: {e}")
            st.session_state["history"].append({"type": "http", "url": url, "result": dict(r.headers), "when": datetime.now().isoformat()})
            if bot.genai_client and st.toggle("AI Analyze HTTP", key="http_ai"):
                st.success(bot.ai(f"Analyze these HTTP headers and server info:\n{dict(r.headers)}"))
        except Exception as e:
            st.error(f"HTTP(s) error: {e}")

with tab4:
    st.markdown("#### <span style='color:#2a5298;'>YARA Rule Builder & File Scanner</span>", unsafe_allow_html=True)
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
        height=220, key="yara_rule_box"
    )
    col1, col2 = st.columns(2)
    with col1:
        if st.button("🛡️ Validate Rule"):
            valid, msg = bot.yara_validate(rule_content)
            st.success(msg) if valid else st.error(msg)
        if st.button("💡 Explain with Gemini"):
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
            if st.button("🔎 Scan Files"):
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

with tab5:
    st.markdown("#### <span style='color:#2a5298;'>Gemini AI Security Chat</span>", unsafe_allow_html=True)
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

# ---- Session History Card Grid ----
if st.session_state["history"]:
    st.markdown("---")
    st.markdown("### 🗂️ Session Scan History")
    for item in reversed(st.session_state["history"][-6:]):
        st.markdown(f"""
            <div style="border:1px solid #d1d7e0;background:#f9fafc;
                border-radius:7px;padding:0.7em 1em;margin-bottom:0.6em;">
                <b>{item['type'].upper()}</b> &nbsp; 
                <span style="color:#7c7c7c;font-size:0.94em;">{item['when']}</span><br>
                <i>{item.get('target', item.get('url',''))}</i>
                <details><summary>View</summary>
                <pre style="font-size:1em;">{str(item['result'])}</pre>
                </details>
            </div>
        """, unsafe_allow_html=True)
        # Optional: Download button per result (as txt)
        st.download_button(f"⬇️ Download ({item['type']})", str(item['result']),
                           file_name=f"scan_{item['type']}_{item['when'].replace(':','-')}.txt")

# ---- Footer ----
st.markdown("""
    <hr style="margin-top:2em;margin-bottom:0;">
    <div style='text-align: center; color: #666; font-size: 1em;'>
        Made with ❤️ by <b>Voxelta Private Limited</b>.<br>
        <a href='https://www.linkedin.com/in/dinesh-k-3199ab1b0/' target='_blank'>Dinesh K on LinkedIn</a>
    </div>
""", unsafe_allow_html=True)
