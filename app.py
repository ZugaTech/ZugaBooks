import streamlit as st

# ————————————————————————————————————————————————
# Page config (MUST be first Streamlit call)
st.set_page_config(
    page_title="ZugaBooks",
    page_icon="📊",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ————————————————————————————————————————————————
import os, time, json
from datetime import date, timedelta
from intuitlib.client import AuthClient
from quickbooks import QuickBooks
import gspread
from oauth2client.service_account import ServiceAccountCredentials
import pandas as pd
from intuitlib.enums import Scopes
from utils import get_report_dataframe, apply_custom_categories
from config import load_config, save_config
from intuitlib.exceptions import AuthClientError
from streamlit_cookies_manager import EncryptedCookieManager

# ————————————————————————————————————————————————
# Cookie secret (24-hour “remember me”)
COOKIE_SECRET = os.getenv("COOKIE_SECRET") or st.secrets.get("general", {}).get("COOKIE_SECRET")
if not COOKIE_SECRET:
    st.error("🔒 Missing COOKIE_SECRET—you must set COOKIE_SECRET as an env var or in .streamlit/secrets.toml")
    st.stop()

cookies = EncryptedCookieManager(
    prefix="zugabooks",
    password=COOKIE_SECRET
)
if not cookies.ready():
    st.stop()

# ————————————————————————————————————————————————
# Secure App Password (once per 24h)
APP_PASSWORD = os.getenv("APP_PASSWORD") or st.secrets.get("APP_PASSWORD", "")
if not APP_PASSWORD:
    st.error("🔒 Missing APP_PASSWORD—you must set APP_PASSWORD as an env var or in .streamlit/secrets.toml")
    st.stop()

def password_gate():
    last_ts = cookies.get("last_auth_ts")
    now = int(time.time())
    if last_ts and now - int(last_ts) < 24 * 3600:
        return  # still within 24h, skip prompt

    st.sidebar.title("🔐 Login Required")
    pw = st.sidebar.text_input("Enter Access Password", type="password", key="password_gate")
    if "authenticated" not in st.session_state:
        st.session_state.authenticated = False

    if pw and pw == APP_PASSWORD:
        st.session_state.authenticated = True
        cookies["last_auth_ts"] = str(now)
        cookies.save()
        st.sidebar.success("✅ Access granted — you won't be asked again for 24 h")
        return
    elif pw:
        st.sidebar.error("❌ Incorrect password")

    st.stop()

password_gate()

password_gate()

# ————————————————————————————————————————————————
# Sidebar: Credentials Manager
def credential_manager():
    cfg = load_config()
    with st.sidebar.expander("🔧 Credentials & Settings", expanded=True):
        st.markdown("### QuickBooks & Google Sheets")

        new_cid = st.text_input("QuickBooks Client ID",
                                value=cfg.get("qb_client_id",""),
                                type="password",
                                key="qb_client_id_input")
        new_secret = st.text_input("QuickBooks Client Secret",
                                   value=cfg.get("qb_client_secret",""),
                                   type="password",
                                   key="qb_client_secret_input")
        new_redirect = st.text_input("QuickBooks Redirect URI",
                                     value=cfg.get("redirect_uri",""),
                                     help="Must *exactly* match Intuit app settings",
                                     key="qb_redirect_uri_input")
        new_realm = st.text_input("QuickBooks Realm ID",
                                  value=cfg.get("realm_id",""),
                                  type="password",
                                  key="qb_realm_id_input")

        new_sheet = st.text_input("Google Sheet ID",
                                  value=cfg.get("sheet_id",""),
                                  key="sheet_id_input")
        sa_file = st.file_uploader("Service Account JSON",
                                   type=["json"],
                                   key="sa_file_uploader")

        if st.button("💾 Save All Credentials", key="save_credentials"):
            updated = False
            for k,v in [
                ("qb_client_id", new_cid),
                ("qb_client_secret", new_secret),
                ("redirect_uri", new_redirect),
                ("realm_id", new_realm),
                ("sheet_id", new_sheet)
            ]:
                if v and v != cfg.get(k):
                    cfg[k] = v
                    updated = True
            if sa_file:
                with open("service_account.json","wb") as f:
                    f.write(sa_file.getbuffer())
                updated = True
            if updated:
                save_config(cfg)
                st.success("✅ Saved settings")
                st.experimental_rerun()
            else:
                st.warning("Nothing changed")

credential_manager()

# ————————————————————————————————————————————————
# QuickBooks OAuth & Token Manager
# ————————————————————————————————————————————————
# QuickBooks OAuth & Token Manager (Fixed Implementation)
class QBTokenManager:
    def __init__(self):
        self.cfg = load_config()
        if not all([self.cfg.get("qb_client_id"),
                    self.cfg.get("qb_client_secret"),
                    self.cfg.get("redirect_uri")]):
            st.error("❌ Please set QuickBooks credentials & redirect URI")
            st.stop()
            
        # Add debug output for credentials
        st.sidebar.write("QB Credentials Status:")
        st.sidebar.write(f"Client ID: {'✅' if self.cfg.get('qb_client_id') else '❌'}")
        st.sidebar.write(f"Client Secret: {'✅' if self.cfg.get('qb_client_secret') else '❌'}")
        st.sidebar.write(f"Redirect URI: {'✅' if self.cfg.get('redirect_uri') else '❌'}")
            
        self.auth_client = AuthClient(
            client_id=self.cfg["qb_client_id"],
            client_secret=self.cfg["qb_client_secret"],
            environment="production",
            redirect_uri=self.cfg["redirect_uri"]
        )

    def handle_oauth(self):
        # Initialize token state
        if "tokens" not in st.session_state:
            st.session_state.tokens = {}
            if self.cfg.get("access_token"):
                st.session_state.tokens = {
                    "access_token": self.cfg["access_token"],
                    "refresh_token": self.cfg["refresh_token"],
                    "expires_at": self.cfg.get("expires_at", 0)
                }

        # Debug token state
        with st.expander("🔍 Token State"):
            st.json(st.session_state.tokens)
            
        toks = st.session_state.tokens

        # 1) Auto-refresh if token exists but is expired
        if toks.get("access_token"):
            if time.time() > toks.get("expires_at", 0):
                try:
                    st.write("🔄 Token expired - attempting refresh...")
                    self.auth_client.refresh_token = toks["refresh_token"]
                    new_tokens = self.auth_client.refresh()
                    
                    # Validate token response
                    if not new_tokens or not hasattr(new_tokens, "access_token"):
                        raise ValueError("Invalid token response from refresh")
                    
                    # Update tokens
                    st.session_state.tokens = {
                        "access_token": new_tokens.access_token,
                        "refresh_token": new_tokens.refresh_token,
                        "expires_at": time.time() + new_tokens.expires_in
                    }
                    
                    # Save to config
                    self.cfg.update({
                        "access_token": new_tokens.access_token,
                        "refresh_token": new_tokens.refresh_token,
                        "expires_at": st.session_state.tokens["expires_at"]
                    })
                    save_config(self.cfg)
                    
                    st.success("✅ Token refreshed successfully!")
                    time.sleep(1)
                    st.experimental_rerun()
                except Exception as e:
                    st.error(f"🔴 Token refresh failed: {str(e)}")
                    st.session_state.tokens = {}
                    return False
            return True

        # 2) Check for authorization code in URL
        params = st.query_params()
        if params.get("code"):
            st.session_state["qb_code"] = params["code"][0]
            st.experimental_rerun()

        # 3) Show authorization prompt
        st.markdown("## Authorize QuickBooks")
        auth_url = self.auth_client.get_authorization_url([Scopes.ACCOUNTING])
        st.markdown(f"""
            ### Steps:
            1. [Click here to authorize]({auth_url})
            2. Log in to QuickBooks and approve access
            3. Copy the authorization code from the URL
        """)
        st.code(f"Redirect URL: {self.auth_client.redirect_uri}")

        code = st.text_input("Paste Authorization Code Here:", 
                             value=st.session_state.get("qb_code", ""),
                             key="qb_auth_code")
        
        if not code:
            st.warning("Please complete the authorization steps")
            st.stop()

        # 4) Exchange code for tokens
        try:
            clean_code = code.strip().split("code=")[-1].split("&")[0]
            st.write(f"ℹ️ Using code: {clean_code[:10]}...")
            
            # Get token response
            token_response = self.auth_client.get_bearer_token(clean_code)
            
            # Validate token response
            if not token_response or not hasattr(token_response, "access_token"):
                raise ValueError("No tokens returned from QuickBooks API")
                
            # Store tokens
            st.session_state.tokens = {
                "access_token": token_response.access_token,
                "refresh_token": token_response.refresh_token,
                "expires_at": time.time() + token_response.expires_in
            }
            
            # Update realm ID if available
            if hasattr(self.auth_client, "realm_id") and self.auth_client.realm_id:
                self.cfg["realm_id"] = self.auth_client.realm_id
                
            # Save tokens to config
            self.cfg.update({
                "access_token": token_response.access_token,
                "refresh_token": token_response.refresh_token,
                "expires_at": st.session_state.tokens["expires_at"]
            })
            save_config(self.cfg)
            
            st.success("✅ Authorization successful! Connecting to QuickBooks...")
            time.sleep(2)
            st.experimental_rerun()
            
        except AuthClientError as e:
            st.error(f"""
                🔴 QuickBooks API Error:
                Status: {e.status_code}
                Content: {e.content}
                Headers: {e.headers}
            """)
            st.stop()
        except Exception as e:
            st.error(f"""
                🔴 Authorization failed: {str(e)}
                Debug Info:
                - Code used: {clean_code[:10]}...
                - Token response type: {type(token_response)}
            """)
            st.stop()
# ————————————————————————————————————————————————
# Main Dashboard
def main_dashboard():
    st.title("📊 Financial Dashboard")
    today = date.today()
    c1, c2 = st.columns(2)
    with c1:
        start = st.date_input("Start Date", today - timedelta(days=30), key="start")
    with c2:
        end = st.date_input("End Date", today, key="end")
    if start > end:
        st.error("End date must be after start"); st.stop()

    rpt = st.selectbox("Report Type",
                       ["ProfitAndLoss","BalanceSheet","TransactionList"],
                       key="rpt")

    m = st.sidebar.file_uploader("CSV: Vendor → Category",
                                 type=["csv"], key="map")
    cat_map = {}
    if m:
        dfm = pd.read_csv(m)
        if {'Vendor','Category'}.issubset(dfm.columns):
            cat_map = dict(zip(dfm['Vendor'], dfm['Category']))
        else:
            st.sidebar.warning("CSV needs Vendor & Category")

    if st.button("🔄 Generate Report", key="gen"):
        with st.spinner("Fetching..."):
            try:
                qb = QuickBooks(
                    auth_client=token_manager.auth_client,
                    access_token=st.session_state.tokens["access_token"],
                    refresh_token=st.session_state.tokens["refresh_token"],
                    company_id=token_manager.cfg.get("realm_id","")
                )
                params = {
                    "start_date": start.strftime("%Y-%m-%d"),
                    "end_date":   end.strftime("%Y-%m-%d")
                }
                rep = qb.get_report(report_name=rpt, params=params)
                df = get_report_dataframe(rep.get("Rows",{}).get("Row",[]), rpt)
                if cat_map:
                    df = apply_custom_categories(df, m)
                st.dataframe(df, use_container_width=True)

                if st.button("📤 Export to Sheets", key="exp"):
                    scope = [
                        "https://spreadsheets.google.com/feeds",
                        "https://www.googleapis.com/auth/drive"
                    ]
                    creds = ServiceAccountCredentials.from_json_keyfile_name(
                        "service_account.json", scope)
                    gc = gspread.authorize(creds)
                    sht = gc.open_by_key(load_config().get("sheet_id",""))
                    try:
                        ws = sht.worksheet(rpt)
                    except:
                        ws = sht.add_worksheet(
                            title=rpt, rows=len(df)+1, cols=len(df.columns))
                    ws.clear()
                    ws.update("A1",
                              [df.columns.tolist()]+df.values.tolist(),
                              value_input_option="USER_ENTERED")
                    st.success("✅ Exported")

                st.download_button("💾 CSV",
                                   data=df.to_csv(index=False),
                                   file_name=f"{rpt}_{today}.csv",
                                   key="dl")
            except Exception as e:
                st.error(f"Failed: {e}")

# ————————————————————————————————————————————————
if __name__ == "__main__":
    token_manager = QBTokenManager()
    if token_manager.handle_oauth():
        main_dashboard()
