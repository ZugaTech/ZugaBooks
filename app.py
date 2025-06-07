import streamlit as st
# ————————————————————————————————————————————————
# MUST be the very first call
st.set_page_config(
    page_title="ZugaBooks",
    page_icon="📊",
    layout="wide",
    initial_sidebar_state="expanded"
)
import os
import time
import json
from datetime import date, timedelta
from pathlib import Path
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
from streamlit import cache_data, query_params
from streamlit import cache_resource


# ————————————————————————————————————————————————
# Cookie + “remember me” setup
COOKIE_SECRET = os.getenv("COOKIE_SECRET") or st.secrets.get("general", {}).get("COOKIE_SECRET")
if not COOKIE_SECRET:
    st.error("🔒 Missing COOKIE_SECRET")
    st.stop()

cookies = EncryptedCookieManager(prefix="zugabooks", password=COOKIE_SECRET)
if not cookies.ready():
    st.stop()

# ————————————————————————————————————————————————
# Password-gate (only once per 24h)
APP_PASSWORD = os.getenv("APP_PASSWORD") or st.secrets.get("APP_PASSWORD", "")
if not APP_PASSWORD:
    st.error("🔒 Missing APP_PASSWORD")
    st.stop()

def password_gate():
    last_ts = cookies.get("last_auth_ts")
    now = int(time.time())
    if last_ts and now - int(last_ts) < 24 * 3600:
        return  # still within 24h

    st.sidebar.title("🔐 Login Required")
    pw = st.sidebar.text_input("Enter Access Password", type="password", key="password_gate")
    if "authenticated" not in st.session_state:
        st.session_state.authenticated = False

    if pw == APP_PASSWORD:
        st.session_state.authenticated = True
        cookies["last_auth_ts"] = str(now)
        cookies.save()
        st.sidebar.success("✅ Access granted — valid for 24 h")
        return
    elif pw:
        st.sidebar.error("❌ Incorrect password")

    st.stop()

password_gate()

# ————————————————————————————————————————————————
# Sidebar: Credentials Manager
def credential_manager():
    cfg = load_config()
    with st.sidebar.expander("🔧 Credentials & Settings", expanded=True):
        st.markdown("### QuickBooks & Google Sheets")

        # QuickBooks Section
        new_cid = st.text_input(
            "QuickBooks Client ID",
            value=cfg.get("qb_client_id", ""),
            type="password",
            key="cred_qb_client_id"
        )
        new_secret = st.text_input(
            "QuickBooks Client Secret",
            value=cfg.get("qb_client_secret", ""),
            type="password",
            key="cred_qb_client_secret"
        )
        new_redirect = st.text_input(
            "QuickBooks Redirect URI",
            value=cfg.get("redirect_uri", ""),
            help="Must match exactly with Intuit Developer Portal",
            key="cred_qb_redirect_uri"
        )
        new_realm = st.text_input(
            "QuickBooks Realm ID",
            value=cfg.get("realm_id", ""),
            type="password",
            key="cred_qb_realm_id"
        )

        # Google Sheets Section
        new_sheet = st.text_input(
            "Google Sheet ID",
            value=cfg.get("google_sheets", {}).get("sheet_id", ""),
            help="From your Google Sheets URL (docs.google.com/spreadsheets/d/[THIS_IS_SHEET_ID]/edit)",
            key="cred_google_sheet_id"
        )
        sa_file = st.file_uploader(
            "Service Account JSON",
            type=["json"],
            help="Download from Google Cloud Console",
            key="cred_sa_file_uploader"
        )

        if st.button("💾 Save All Credentials", key="cred_save_button"):
            updated = False

            # QuickBooks Updates
            for k, v in [
                ("qb_client_id", new_cid),
                ("qb_client_secret", new_secret),
                ("redirect_uri", new_redirect),
                ("realm_id", new_realm)
            ]:
                if v and v != cfg.get(k):
                    cfg[k] = v
                    updated = True

            # Google Sheets Updates
            if new_sheet and new_sheet != cfg.get("google_sheets", {}).get("sheet_id", ""):
                if "google_sheets" not in cfg:
                    cfg["google_sheets"] = {}
                cfg["google_sheets"]["sheet_id"] = new_sheet
                updated = True

            # Service Account File
            if sa_file:
                with open("service_account.json", "wb") as f:
                    f.write(sa_file.getbuffer())
                updated = True

            if updated:
                # Save to both encrypted and plaintext (for emergency recovery)
                save_config(cfg, force_plaintext=True)
                st.success("✅ Configuration saved successfully!")
                st.balloons()
                # Clear caches and restart
                from streamlit import cache_data
                cache_data.clear()
                st.experimental_rerun()
            else:
                st.warning("⚠️ No changes detected")

# Show config debug if checkbox ticked
with st.sidebar:
    if st.checkbox("🔍 Show Config Debug", False):
        from datetime import datetime
        current_config = load_config()
        st.write("### Config Status")
        st.json({
            "source": "🔒 Encrypted" if Path("config.enc").exists() else "📄 Plaintext",
            "quickbooks_configured": bool(current_config.get("qb_client_id")),
            "google_sheets_configured": bool(current_config.get("google_sheets", {}).get("sheet_id")),
            "last_modified": (
                datetime.fromtimestamp(Path("config.enc").stat().st_mtime).isoformat()
                if Path("config.enc").exists()
                else "Never"
            )
        })

credential_manager()

# ————————————————————————————————————————————————
# ————————————————————————————————————————————————
class QBTokenManager:
    def __init__(self):
        self.cfg = load_config()
        for f in ("qb_client_id","qb_client_secret","redirect_uri"):
            if not self.cfg.get(f):
                st.error(f"❌ Missing {f} in config")
                st.stop()
        self.auth_client = AuthClient(
            client_id=self.cfg["qb_client_id"],
            client_secret=self.cfg["qb_client_secret"],
            environment="production",
            redirect_uri=self.cfg["redirect_uri"],
        )
        st.session_state.setdefault("tokens", {})
    
    def handle_oauth(self) -> bool:
        toks = st.session_state.tokens
        
        # If we already have a valid, unexpired access_token, we’re done:
        if toks.get("access_token") and time.time() < toks.get("expires_at",0):
            return True
        
        st.markdown("## 🔑 Connect to QuickBooks")
        st.markdown(f"[1) Authorize →]({self.auth_client.get_authorization_url([Scopes.ACCOUNTING])})")
        st.info(f"Your redirect URI: `{self.auth_client.redirect_uri}`")
        
        code = st.text_input("2) Paste **authorization code** here", key="qb_manual_code")
        if not code:
            st.stop()
        
        # User did paste something—try to exchange it now:
        try:
            token_resp = self.auth_client.get_bearer_token(code.strip())
            # Validate:
            if "access_token" not in token_resp:
                raise ValueError("no access_token in response")
            
            # Save to session + config
            expires = time.time() + token_resp["expires_in"]
            st.session_state.tokens = {
                "access_token": token_resp["access_token"],
                "refresh_token": token_resp["refresh_token"],
                "expires_at": expires,
            }
            self.cfg.update(st.session_state.tokens)
            # also save realmId if provided
            if "realmId" in token_resp:
                self.cfg["realm_id"] = token_resp["realmId"]
            save_config(self.cfg)
            
            st.success("✅ QuickBooks connected!")
            st.experimental_rerun()
        except Exception as e:
            st.error(f"🔴 Authorization failed: {e}")
            st.stop()

# ————————————————————————————————————————————————
def main_dashboard():
    st.title("📊 Financial Dashboard")
    today = date.today()

    col1, col2 = st.columns(2)
    with col1:
        start = st.date_input("Start Date", today - timedelta(days=30), key="start")
    with col2:
        end = st.date_input("End Date", today, key="end")

    if start > end:
        st.error("⚠️ End date must be after start date.")
        st.stop()

    rpt = st.selectbox(
        "Select Report Type",
        ["ProfitAndLoss", "BalanceSheet", "TransactionList"],
        key="rpt"
    )

    # Vendor→Category mapping
    m = st.sidebar.file_uploader("CSV: Vendor→Category", type=["csv"], key="map")
    cat_map = {}
    if m:
        try:
            dfm = pd.read_csv(m)
            if {'Vendor', 'Category'}.issubset(dfm.columns):
                cat_map = dict(zip(dfm['Vendor'], dfm['Category']))
            else:
                st.sidebar.warning("CSV must contain 'Vendor' and 'Category' columns.")
        except Exception as e:
            st.sidebar.error(f"Error reading CSV: {str(e)}")

    if st.button("🔄 Generate Report", key="gen"):
        with st.spinner("Fetching report…"):
            try:
                qb = QuickBooks(
                    auth_client=token_manager.auth_client,
                    access_token=st.session_state.tokens["access_token"],
                    refresh_token=st.session_state.tokens["refresh_token"],
                    company_id=token_manager.cfg.get("realm_id", "")
                )

                params = {
                    "start_date": start.strftime("%Y-%m-%d"),
                    "end_date": end.strftime("%Y-%m-%d")
                }
                rep = qb.get_report(report_name=rpt, params=params)
                df = get_report_dataframe(rep.get("Rows", {}).get("Row", []), rpt)

                if cat_map:
                    df = apply_custom_categories(df, m)

                st.subheader(f"{rpt} Report")
                st.dataframe(df, use_container_width=True)

                if st.button("📤 Export to Google Sheets", key="exp"):
                    try:
                        cfg = load_config()
                        sheet_id = cfg.get("google_sheets", {}).get("sheet_id", "")
                        if not sheet_id:
                            st.error("❌ Google Sheet ID is not configured")
                            return

                        scope = [
                            "https://spreadsheets.google.com/feeds",
                            "https://www.googleapis.com/auth/drive"
                        ]
                        creds = ServiceAccountCredentials.from_json_keyfile_name(
                            "service_account.json", scope
                        )
                        gc = gspread.authorize(creds)

                        sheet = gc.open_by_key(sheet_id)
                        try:
                            worksheet = sheet.worksheet(rpt)
                        except gspread.exceptions.WorksheetNotFound:
                            worksheet = sheet.add_worksheet(
                                title=rpt,
                                rows=len(df) + 1,
                                cols=len(df.columns)
                            )

                        worksheet.clear()
                        worksheet.update(
                            "A1",
                            [df.columns.tolist()] + df.values.tolist(),
                            value_input_option="USER_ENTERED"
                        )
                        st.success("✅ Successfully exported to Google Sheets!")
                    except Exception as e:
                        st.error(f"🔴 Export failed: {str(e)}")

                st.download_button(
                    label="💾 Download CSV",
                    data=df.to_csv(index=False),
                    file_name=f"{rpt}_{today}.csv",
                    mime="text/csv",
                    key="dl"
                )

            except Exception as e:
                st.error(f"❌ Report generation failed: {str(e)}")

# ————————————————————————————————————————————————
if __name__ == "__main__":
    # Reset QuickBooks authorization if needed
    if st.sidebar.button("🔄 Reset QuickBooks Authorization", key="reset_qb_auth"):
        st.session_state.pop("tokens", None)
        st.session_state.qb_auth_phase = "init"
        cfg = load_config()
        for k in ("access_token", "refresh_token", "expires_at", "realm_id"):
            cfg.pop(k, None)
        save_config(cfg)
        st.success("Authorization reset—please reauthorize")
        time.sleep(1)
        st.rerun()

    # Initialize token manager
    token_manager = QBTokenManager()

    # Show connection status
    if st.session_state.get("qb_auth_phase", "") == "complete":
        st.sidebar.success("✅ Connected to QuickBooks")
    else:
        st.sidebar.warning("🔴 Not connected to QuickBooks")

    # Main flow
    if token_manager.handle_oauth():
        main_dashboard()

    # DEBUG MODE (optional)
    if os.getenv("DEBUG_MODE"):
        st.sidebar.subheader("🔧 Debug Console")
        if st.sidebar.button("Validate Config"):
            try:
                cfg = load_config()
                st.sidebar.success("Config valid!")
                st.sidebar.json({k: ("****" if 'secret' in k else v) for k, v in cfg.items()})
            except Exception as e:
                st.sidebar.error(f"Config error: {str(e)}")
        if st.sidebar.button("Test QuickBooks Connection"):
            try:
                qb = QuickBooks(
                    auth_client=token_manager.auth_client,
                    access_token=st.session_state.tokens["access_token"],
                    company_id=token_manager.cfg.get("realm_id", "")
                )
                info = qb.get_company_info()
                st.sidebar.success(f"Connected to: {info['CompanyName']}")
            except Exception as e:
                st.sidebar.error(f"Connection failed: {str(e)}")
        if st.sidebar.button("Test Google Sheets Connection"):
            try:
                scope = [
                    "https://spreadsheets.google.com/feeds",
                    "https://www.googleapis.com/auth/drive"
                ]
                creds = ServiceAccountCredentials.from_json_keyfile_name("service_account.json", scope)
                gc = gspread.authorize(creds)
                sheet_id = load_config().get("google_sheets", {}).get("sheet_id", "")
                if not sheet_id:
                    st.sidebar.error("Missing sheet ID")
                else:
                    sheet = gc.open_by_key(sheet_id)
                    st.sidebar.success(f"Access to: {sheet.title}")
            except Exception as e:
                st.sidebar.error(f"Sheets connection failed: {str(e)}")
