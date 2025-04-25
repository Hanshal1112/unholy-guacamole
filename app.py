import streamlit as st
import requests
import hashlib
import subprocess
from email_validator import validate_email, EmailNotValidError

st.set_page_config(page_title="OSINT Email & IP Investigator", page_icon="🔍", layout="centered")
st.markdown("""
    <style>
    .stTextInput>div>div>input {
        font-size: 18px;
    }
    .stButton>button {
        font-size: 18px;
        font-weight: bold;
    }
    </style>
""", unsafe_allow_html=True)

# ------------------ 1. EMAIL VALIDATION ------------------
def validate_user_email(email):
    try:
        v = validate_email(email)
        return f"✅ '{email}' is a valid email address."
    except EmailNotValidError as e:
        return f"❌ Email validation error: {str(e)}"

# ------------------ 2. CHECK BREACHED SITES ------------------
def check_breaches(email):
    url = f"https://api.xposedornot.com/v1/check-email/{email}"
    try:
        response = requests.get(url)
        if response.status_code == 200:
            data = response.json()
            if data.get("breaches"):
                breaches = [f"🔴 {b['breach_name']} (Leaked: {b['leak_date']})" for b in data["breaches"]]
                return "\n".join(breaches)
            else:
                return "✅ No known breaches found."
        elif response.status_code == 404:
            return "✅ No breach data found."
        else:
            return f"⚠ Unexpected response: {response.status_code}"
    except Exception as e:
        return f"❌ Error checking breaches: {e}"

# ------------------ 3. PASTEBIN DUMPS ------------------
def check_psbdmp(email):
    try:
        url = f"https://psbdmp.ws/api/search/{email}"
        response = requests.get(url)
        if response.status_code == 200:
            data = response.json()
            if 'data' in data and len(data['data']) > 0:
                return "\n".join([f"🔗 https://psbdmp.ws/api/dump/{d}" for d in data["data"][:5]])
            else:
                return "✅ No dumps found."
        else:
            return "✅ No dumps found or rate-limited."
    except Exception as e:
        return f"❌ Error checking PSBDMP: {e}"

# ------------------ 4. IP LOOKUP ------------------
def ip_lookup(ip):
    try:
        url = f"https://ipapi.co/{ip}/json/"
        headers = {'User-Agent': 'Mozilla/5.0'}  # Required for free tier
        response = requests.get(url, headers=headers)
        data = response.json()
        if 'error' in data:
            return f"❌ IPAPI Error: {data.get('reason', 'Unknown error')}"
        return "\n".join([
            f"📍 IP: {data.get('ip', 'N/A')}",
            f"📍 City: {data.get('city', 'N/A')}",
            f"📍 Region: {data.get('region', 'N/A')}",
            f"📍 Country: {data.get('country_name', 'N/A')}",
            f"📍 Org: {data.get('org', 'N/A')}",
            f"📍 ASN: {data.get('asn', 'N/A')}",
            f"📍 Latitude: {data.get('latitude', 'N/A')}",
            f"📍 Longitude: {data.get('longitude', 'N/A')}",
        ])
    except Exception as e:
        return f"❌ Error in IP lookup: {e}"

# ------------------ 5. EMAIL ACTIVITY CHECK ------------------
def check_email_activity(email):
    api_key = "2550ddf39b5d4eb48dc46c1d8a54e71b"
    try:
        url = f"https://emailvalidation.abstractapi.com/v1/?api_key={api_key}&email={email}"
        response = requests.get(url)
        data = response.json()
        return f"📬 Deliverability: {data.get('deliverability')}\n📌 Valid Format: {data.get('is_valid_format', {}).get('value')}\n📡 MX Found: {data.get('mx_found')}"
    except Exception as e:
        return f"❌ Error checking Abstract API: {e}"

# ------------------ 6. FIND RELATED EMAILS ------------------
def find_related_emails(email):
    api_key = "34b11512752ce32168664e4110d962c79f8f7a90"
    domain = email.split('@')[-1]
    try:
        url = f"https://api.hunter.io/v2/domain-search?domain={domain}&api_key={api_key}"
        response = requests.get(url)
        data = response.json()
        emails = data.get("data", {}).get("emails", [])
        return "\n".join([f"📧 {e.get('value')} (Type: {e.get('type')})" for e in emails[:5]]) if emails else "✅ No related emails found."
    except Exception as e:
        return f"❌ Error querying Hunter API: {e}"

# ------------------ 7. SOCIAL MEDIA & USERNAME PRESENCE ------------------
def check_social_media_presence(email):
    try:
        username = email.split('@')[0]
        result = subprocess.run(['socialscan', username], capture_output=True, text=True)
        return result.stdout or "✅ No presence detected."
    except Exception as e:
        return f"❌ Error checking social media presence: {e}"

# ------------------ 8. GRAVATAR PROFILE CHECK ------------------
def check_gravatar(email):
    try:
        hashed = hashlib.md5(email.strip().lower().encode()).hexdigest()
        url = f"https://www.gravatar.com/avatar/{hashed}?d=404"
        response = requests.get(url)
        if response.status_code == 200:
            return f"🖼 Gravatar profile found: https://www.gravatar.com/avatar/{hashed}"
        else:
            return "✅ No Gravatar profile found."
    except Exception as e:
        return f"❌ Error checking Gravatar: {e}"

# ------------------ 9. GITHUB ACCOUNT CHECK ------------------
def check_github(email):
    try:
        username = email.split('@')[0]
        url = f"https://github.com/{username}"
        response = requests.get(url)
        return f"🐙 GitHub profile found: {url}" if response.status_code == 200 else "✅ No GitHub profile found."
    except Exception as e:
        return f"❌ Error checking GitHub: {e}"

# ------------------ 10. PGP PUBLIC KEY CHECK ------------------
def check_pgp_key(email):
    try:
        url = f"https://keys.openpgp.org/vks/v1/by-email/{email}"
        response = requests.get(url)
        if response.status_code == 200 and "-----BEGIN PGP PUBLIC KEY BLOCK-----" in response.text:
            return "🔐 Public PGP key found."
        else:
            return "✅ No public PGP key found."
    except Exception as e:
        return f"❌ Error checking PGP key: {e}"

# ------------------ STREAMLIT APP ------------------
st.title("🔎 OSINT Email & IP Investigator")
st.write("Enter an email or IP address to gather publicly available intelligence data across various online sources.")

email = st.text_input("📧 Email Address")
ip = st.text_input("🌐 IP Address")

st.sidebar.header("🧰 Module Toggle")
run_email_validation = st.sidebar.checkbox("Email Validation", True)
run_breach_check = st.sidebar.checkbox("Check Breaches", True)
run_pastebin_check = st.sidebar.checkbox("Pastebin Dumps", True)
run_email_activity = st.sidebar.checkbox("Email Activity", True)
run_related_emails = st.sidebar.checkbox("Related Emails", True)
run_social_check = st.sidebar.checkbox("Social Media Presence", True)
run_gravatar_check = st.sidebar.checkbox("Gravatar Profile", True)
run_github_check = st.sidebar.checkbox("GitHub Account", True)
run_pgp_check = st.sidebar.checkbox("PGP Public Key", True)
run_ip_lookup = st.sidebar.checkbox("IP Lookup", True)

if st.button("🔍 Run OSINT Scan"):
    with st.spinner("Investigating..."):
        if email:
            st.header("📧 Email Intelligence Report")
            if run_email_validation:
                st.success(validate_user_email(email))
            if run_breach_check:
                st.info(check_breaches(email))
            if run_pastebin_check:
                st.info(check_psbdmp(email))
            if run_email_activity:
                st.info(check_email_activity(email))
            if run_related_emails:
                st.info(find_related_emails(email))
            if run_social_check:
                st.info(check_social_media_presence(email))
            if run_gravatar_check:
                st.info(check_gravatar(email))
            if run_github_check:
                st.info(check_github(email))
            if run_pgp_check:
                st.info(check_pgp_key(email))

        if ip and run_ip_lookup:
            st.header("🌐 IP Address Report")
            st.info(ip_lookup(ip))
