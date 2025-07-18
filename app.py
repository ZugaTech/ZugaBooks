import streamlit as st
import time
from streamlit_cookies_manager import EncryptedCookieManager

# Initialize cookies
cookies = EncryptedCookieManager(prefix="myapp/", password="your-secret-key-here")
if not cookies.ready():
    st.stop()

# Define constants
APP_PASSWORD = "your_password_here"  # Replace with your actual password

def password_gate():
    # Check if authenticated via cookie timestamp
    last_ts = cookies.get("last_auth_ts")
    now = int(time.time())
    if last_ts and now - int(last_ts) < 24 * 3600:
        st.session_state.authenticated = True
        return

    # Initialize authentication state
    if "authenticated" not in st.session_state:
        st.session_state.authenticated = False

    # If already authenticated, proceed
    if st.session_state.authenticated:
        return

    # Display password input in sidebar
    st.sidebar.title("🔐 Login Required")
    pw = st.sidebar.text_input("Enter Access Password", type="password", key="password_gate")

    if pw == APP_PASSWORD:
        st.session_state.authenticated = True
        cookies["last_auth_ts"] = str(now)
        cookies.save()
        st.sidebar.success("✅ Access granted — valid for 24 h")
        st.rerun()  # Rerun to refresh state
    elif pw:
        st.sidebar.error("❌ Incorrect password")
        st.stop()  # Stop execution if password is incorrect
    else:
        st.stop()  # Stop execution if no password is entered

def credential_manager():
    st.sidebar.subheader("🔑 Credentials Settings")
    st.sidebar.write("Here you can manage your credentials.")
    # Add your credential management logic here

def main_dashboard():
    st.title("Main Dashboard")
    st.write("Welcome to the authenticated dashboard!")

class QBTokenManager:
    def __init__(self):
        self._init_token_state()

    def _init_token_state(self):
        if "tokens" not in st.session_state:
            st.session_state.tokens = {}

    def handle_oauth(self):
        # Placeholder for OAuth handling
        if st.session_state.tokens.get("access_token"):
            return True
        else:
            st.sidebar.write("Please authorize QuickBooks.")
            return False

if __name__ == "__main__":
    password_gate()
    credential_manager()
    token_manager = QBTokenManager()
    if st.sidebar.button("🔄 Reset QuickBooks Authorization", key="reset_qb_auth"):
        st.session_state.pop("tokens", None)
        st.success("Auth reset—please reauthorize")
        time.sleep(1)
        st.rerun()

    if st.session_state.tokens.get("access_token"):
        st.sidebar.success("✅ Connected to QuickBooks")
    else:
        st.sidebar.warning("🔴 Not connected to QuickBooks")

    if token_manager.handle_oauth():
        main_dashboard()
