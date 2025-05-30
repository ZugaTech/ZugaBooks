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
# ————————————————————————————————————————————————
# QuickBooks OAuth & Token Manager (Fixed with st.query_params)
class QBTokenManager:
    def __init__(self):
        self.cfg = load_config()
        self._verify_credentials()
        self.auth_client = AuthClient(
            client_id=self.cfg["qb_client_id"],
            client_secret=self.cfg["qb_client_secret"],
            environment="production",
            redirect_uri=self.cfg["redirect_uri"]
        )
        self._init_session_state()
        st.query_params()  # Initialize query params

    def _verify_credentials(self):
        """Hard validation of required credentials"""
        missing = []
        for field in ['qb_client_id', 'qb_client_secret', 'redirect_uri']:
            if not self.cfg.get(field):
                missing.append(field)
        if missing:
            st.error(f"❌ Missing required config: {', '.join(missing)}")
            st.stop()

    def _init_session_state(self):
        """Initialize all required session state variables"""
        defaults = {
            'qb_auth_phase': 'init',  # init → code_exchange → complete
            'tokens': {
                'access_token': self.cfg.get('access_token'),
                'refresh_token': self.cfg.get('refresh_token'),
                'expires_at': self.cfg.get('expires_at', 0)
            }
        }
        
        for key, value in defaults.items():
            if key not in st.session_state:
                st.session_state[key] = value

    def handle_oauth(self) -> bool:
        """Main OAuth handler with guaranteed state progression"""
        # 1. Debug view (temporary)
        with st.expander("Auth State", expanded=False):
            st.json({
                "phase": st.session_state.qb_auth_phase,
                "tokens": {k: "****" if "token" in k else v 
                          for k,v in st.session_state.tokens.items()}
            })

        # 2. Check for valid tokens
        if self._has_valid_tokens():
            return True
            
        # 3. State machine for OAuth flow
        if st.session_state.qb_auth_phase == 'init':
            self._start_authorization()
        elif st.session_state.qb_auth_phase == 'code_exchange':
            self._exchange_authorization_code()
            
        st.info("🔒 QuickBooks authorization in progress...")
        st.stop()

    def _has_valid_tokens(self) -> bool:
        """Check if valid tokens exist and refresh if needed"""
        tokens = st.session_state.tokens
        
        # No tokens available
        if not tokens.get('access_token'):
            return False
            
        # Token expired - try refresh
        if time.time() > tokens.get('expires_at', 0):
            try:
                st.write("🔄 Refreshing expired token...")
                new_tokens = self._refresh_tokens(tokens['refresh_token'])
                
                # Update state
                st.session_state.tokens = new_tokens
                st.session_state.qb_auth_phase = 'complete'
                
                # Persist to config
                self.cfg.update(new_tokens)
                save_config(self.cfg)
                
                st.success("✅ Token refreshed successfully!")
                time.sleep(1)
                st.rerun()
            except Exception as e:
                st.error(f"🔴 Token refresh failed: {str(e)}")
                return False
        return True

    def _start_authorization(self):
        """Phase 1: Initiate OAuth flow"""
        # Check for callback in URL
        params = st.query_params()
        if 'code' in params:
            st.session_state.qb_auth_phase = 'code_exchange'
            st.session_state.qb_code = params['code'][0]
            st.rerun()
            
        # Show authorization prompt
        st.markdown("## 🔑 QuickBooks Authorization")
        auth_url = self.auth_client.get_authorization_url([Scopes.ACCOUNTING])
        
        st.markdown(f"""
            ### Steps:
            1. [Click here to authorize]({auth_url})
            2. Log in to QuickBooks and approve access
            3. You'll be redirected back to this app
        """)
        
        st.info(f"**Redirect URI:** `{self.auth_client.redirect_uri}`")

    def _exchange_authorization_code(self):
        """Phase 2: Exchange code for tokens"""
        if 'qb_code' not in st.session_state:
            st.error("Authorization code missing")
            st.session_state.qb_auth_phase = 'init'
            st.rerun()

        try:
            code = st.session_state.qb_code
            clean_code = code.split('code=')[-1].split('&')[0].strip()
            st.write(f"ℹ️ Exchanging authorization code: {clean_code[:8]}...")
            
            # Get tokens
            token_response = self.auth_client.get_bearer_token(clean_code)
            
            # Validate response
            if not token_response or not hasattr(token_response, 'access_token'):
                raise ValueError("Invalid token response from QuickBooks")
                
            # Store tokens
            new_tokens = {
                'access_token': token_response.access_token,
                'refresh_token': token_response.refresh_token,
                'expires_at': time.time() + token_response.expires_in
            }
            
            # Update state
            st.session_state.tokens = new_tokens
            st.session_state.qb_auth_phase = 'complete'
            
            # Save realm ID if available
            if hasattr(self.auth_client, 'realm_id') and self.auth_client.realm_id:
                self.cfg['realm_id'] = self.auth_client.realm_id
                
            # Persist tokens
            self.cfg.update(new_tokens)
            save_config(self.cfg)
            
            # Clear URL parameters
            st.query_params.clear()
            
            st.success("✅ Authorization successful! Loading dashboard...")
            time.sleep(2)
            st.rerun()
            
        except AuthClientError as e:
            st.error(f"""
                🔴 QuickBooks API Error:
                Status: {e.status_code}
                {e.content}
            """)
            st.session_state.qb_auth_phase = 'init'
            st.rerun()
        except Exception as e:
            st.error(f"🔴 Authorization failed: {str(e)}")
            st.session_state.qb_auth_phase = 'init'
            st.rerun()

    def _refresh_tokens(self, refresh_token: str) -> dict:
        """Refresh access tokens using refresh token"""
        self.auth_client.refresh_token = refresh_token
        new_tokens = self.auth_client.refresh()
        
        if not new_tokens or not hasattr(new_tokens, 'access_token'):
            raise ValueError("Invalid refresh token response")
            
        return {
            'access_token': new_tokens.access_token,
            'refresh_token': new_tokens.refresh_token,
            'expires_at': time.time() + new_tokens.expires_in
        }


# ————————————————————————————————————————————————
# Main Dashboard
def main_dashboard():
    st.title("📊 Financial Dashboard")
    today = date.today()

    col1, col2 = st.columns(2)
    with col1:
        start_date = st.date_input("Start Date", today - timedelta(days=30), key="start")
    with col2:
        end_date = st.date_input("End Date", today, key="end")

    if start_date > end_date:
        st.error("⚠️ End date must be after start date.")
        st.stop()

    report_type = st.selectbox(
        "Select Report Type",
        ["ProfitAndLoss", "BalanceSheet", "TransactionList"],
        key="report_type"
    )

    # Optional CSV mapping file
    mapping_file = st.sidebar.file_uploader("CSV: Vendor → Category", type=["csv"], key="vendor_mapping")
    category_map = {}
    if mapping_file:
        df_map = pd.read_csv(mapping_file)
        if {'Vendor', 'Category'}.issubset(df_map.columns):
            category_map = dict(zip(df_map['Vendor'], df_map['Category']))
        else:
            st.sidebar.warning("❌ CSV must contain 'Vendor' and 'Category' columns.")

    if st.button("🔄 Generate Report", key="generate_report"):
        with st.spinner("📡 Fetching data from QuickBooks..."):
            try:
                qb = QuickBooks(
                    auth_client=token_manager.auth_client,
                    access_token=st.session_state.tokens["access_token"],
                    refresh_token=st.session_state.tokens["refresh_token"],
                    company_id=token_manager.cfg.get("realm_id", "")
                )

                params = {
                    "start_date": start_date.strftime("%Y-%m-%d"),
                    "end_date": end_date.strftime("%Y-%m-%d")
                }

                report = qb.get_report(report_name=report_type, params=params)
                rows = report.get("Rows", {}).get("Row", [])
                df = get_report_dataframe(rows, report_type)

                if category_map:
                    df = apply_custom_categories(df, mapping_file)

                st.subheader(f"{report_type} Report")
                st.dataframe(df, use_container_width=True)

                # Export to Google Sheets
                if st.button("📤 Export to Google Sheets", key="export_sheets"):
                    scope = [
                        "https://spreadsheets.google.com/feeds",
                        "https://www.googleapis.com/auth/drive"
                    ]
                    creds = ServiceAccountCredentials.from_json_keyfile_name(
                        "service_account.json", scope
                    )
                    gc = gspread.authorize(creds)
                    sheet = gc.open_by_key(load_config().get("sheet_id", ""))
                    try:
                        worksheet = sheet.worksheet(report_type)
                    except gspread.exceptions.WorksheetNotFound:
                        worksheet = sheet.add_worksheet(
                            title=report_type,
                            rows=len(df) + 1,
                            cols=len(df.columns)
                        )
                    worksheet.clear()
                    worksheet.update("A1", [df.columns.tolist()] + df.values.tolist(), value_input_option="USER_ENTERED")
                    st.success("✅ Successfully exported to Google Sheets!")

                # Download CSV
                st.download_button(
                    label="💾 Download CSV",
                    data=df.to_csv(index=False),
                    file_name=f"{report_type}_{today}.csv",
                    mime="text/csv",
                    key="download_csv"
                )

            except Exception as e:
                st.error(f"❌ Report generation failed: {e}")
                

# ————————————————————————————————————————————————
# App Entry Point
if __name__ == "__main__":
    token_manager = QBTokenManager()

    # Status UI
    if st.session_state.get("tokens", {}).get("access_token"):
        st.sidebar.success("✅ Connected to QuickBooks")
    else:
        st.sidebar.warning("🔴 Not connected to QuickBooks")

    # Run dashboard only if authenticated
    if token_manager.handle_oauth():
        main_dashboard()
