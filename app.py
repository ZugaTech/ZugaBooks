import streamlit as st
import os
import time
import json
from datetime import date, timedelta
from intuitlib.client import AuthClient
from quickbooks import QuickBooks
import gspread
from oauth2client.service_account import ServiceAccountCredentials
import pandas as pd
from intuitlib.enums import Scopes
from cryptography.fernet import Fernet
from utils import get_report_dataframe, apply_custom_categories
from config import load_config, save_config
from typing import Dict, Any

# --- Streamlit App Configuration ---
st.set_page_config(
    page_title="ZugaBooks",
    page_icon="📊",
    layout="wide",
    initial_sidebar_state="expanded"
)

# --- Load APP_PASSWORD safely ---
APP_PASSWORD = os.environ.get("APP_PASSWORD", "")
if not APP_PASSWORD:
    try:
        APP_PASSWORD = st.secrets["APP_PASSWORD"]
    except Exception:
        APP_PASSWORD = ""

# --- PASSWORD PROTECTION (sidebar) ---
def password_gate():
    st.sidebar.title("🔐 Login Required")
    pw = st.sidebar.text_input("Enter Access Password", type="password")
    if "authenticated" not in st.session_state:
        st.session_state.authenticated = False

    if pw and APP_PASSWORD and pw == APP_PASSWORD:
        st.session_state.authenticated = True
        st.sidebar.success("✅ Access granted")
    elif pw:
        st.sidebar.error("❌ Incorrect password")

    if not st.session_state.authenticated:
        st.stop()

password_gate()

# --- Credential Management UI ---
def credential_manager() -> None:
    with st.sidebar.expander("🔐 Credential Configuration", expanded=False):
        st.markdown("### 🔑 API Credentials")
        cfg = load_config()

        new_client_id = st.text_input(
            "QuickBooks Client ID", type="password", value=cfg.get("qb_client_id", "")
        )
        new_client_secret = st.text_input(
            "QuickBooks Client Secret", type="password", value=cfg.get("qb_client_secret", "")
        )
        new_realm_id = st.text_input(
            "QuickBooks Realm ID", type="password", value=cfg.get("realm_id", "")
        )
        new_sheet_id = st.text_input(
            "Google Sheet ID", type="password", value=cfg.get("sheet_id", "")
        )
        sa_file = st.file_uploader("Google Service Account JSON", type=["json"])

        if st.button("💾 Save All Credentials"):
            updated = False
            if new_client_id:
                cfg["qb_client_id"] = new_client_id; updated = True
            if new_client_secret:
                cfg["qb_client_secret"] = new_client_secret; updated = True
            if new_realm_id:
                cfg["realm_id"] = new_realm_id; updated = True
            if new_sheet_id:
                cfg["sheet_id"] = new_sheet_id; updated = True
            if sa_file:
                with open("service_account.json", "wb") as f:
                    f.write(sa_file.getbuffer())
                updated = True
            if updated:
                save_config(cfg)
                st.success("Credentials securely stored!")
            else:
                st.warning("No changes detected")

# --- QuickBooks OAuth Flow with Auto-Refresh & Fallback ---
class QBTokenManager:
    def __init__(self):
        self.cfg = load_config()
        self.auth_client = AuthClient(
            client_id=self.cfg.get("qb_client_id", ""),
            client_secret=self.cfg.get("qb_client_secret", ""),
            environment="production",
            redirect_uri=self.cfg.get("redirect_uri", ""),
            realm_id=self.cfg.get("realm_id", "")
        )

    def handle_oauth(self) -> bool:
        toks = st.session_state.get("tokens", {})

        # Auto-refresh logic
        if toks:
            if time.time() > toks.get("expires_at", 0):
                try:
                    new = self.auth_client.refresh(toks["refresh_token"])
                    st.session_state.tokens = {
                        "access_token": new["accessToken"],
                        "refresh_token": new["refreshToken"],
                        "expires_at": time.time() + new.get("expires_in", 3600)
                    }
                    self.cfg.update({
                        "access_token": new["accessToken"],
                        "refresh_token": new["refreshToken"]
                    })
                    save_config(self.cfg)
                    return True
                except Exception:
                    st.session_state.pop("tokens")
                    st.warning("🔄 Session expired, please re-authorize.")
            else:
                return True

        # No valid tokens → show auth UI
        url = self.auth_client.get_authorization_url([Scopes.ACCOUNTING])
        st.markdown("### 🔗 Connect to QuickBooks")
        st.markdown(f"[Authorize QuickBooks]({url})", unsafe_allow_html=True)

        code = st.text_input("Paste the 'code' from QuickBooks URL here")
        if not code:
            st.stop()

        try:
            cleaned = code.strip().split("&")[0].split("=")[-1]
            tokens = self.auth_client.get_bearer_token(cleaned)
            st.session_state.tokens = {
                "access_token": tokens["accessToken"],
                "refresh_token": tokens["refreshToken"],
                "expires_at": time.time() + tokens.get("expires_in", 3600)
            }
            self.cfg.update({
                "realm_id": tokens.get("realmId", self.cfg.get("realm_id")),
                "access_token": tokens["accessToken"],
                "refresh_token": tokens["refreshToken"]
            })
            save_config(self.cfg)
            st.success("✅ QuickBooks connected!")
            st.rerun()
        except Exception as e:
            st.error(f"Authorization failed: {e}")
            st.stop()

# --- Main App Interface ---
def main_dashboard() -> None:
    st.title("📊 Financial Dashboard")
    today = date.today()
    c1, c2 = st.columns(2)
    with c1:
        start = st.date_input("Start Date", today - timedelta(days=30))
    with c2:
        end = st.date_input("End Date", today)
    if start > end:
        st.error("⚠️ End date must be after start date"); st.stop()

    report_type = st.selectbox("Select Report Type", ["ProfitAndLoss", "BalanceSheet", "TransactionList"])

    mapping_file = st.sidebar.file_uploader("Upload CSV mapping: Vendor → Category", type=["csv"])
    category_map = {}
    if mapping_file:
        df_map = pd.read_csv(mapping_file)
        if {'Vendor','Category'}.issubset(df_map.columns):
            category_map = dict(zip(df_map['Vendor'], df_map['Category']))
        else:
            st.sidebar.warning("CSV needs 'Vendor' & 'Category' columns.")

    if st.button("🔄 Generate Report"):
        with st.spinner("📡 Fetching..."):
            try:
                client = QuickBooks(
                    auth_client=token_manager.auth_client,
                    company_id=token_manager.cfg.get("realm_id",""),
                    refresh_token=st.session_state.tokens["refresh_token"]
                )
                params = {"start_date": start.strftime('%Y-%m-%d'), "end_date": end.strftime('%Y-%m-%d')}
                rpt = client.get_report(report_name=report_type, params=params)
                df = get_report_dataframe(rpt.get('Rows',{}).get('Row',[]), report_type)
                if category_map:
                    df = apply_custom_categories(df, mapping_file)
                st.subheader(f"{report_type} Report"); st.dataframe(df, use_container_width=True)

                if st.button("📤 Export to Google Sheets"):
                    scope = ["https://spreadsheets.google.com/feeds","https://www.googleapis.com/auth/drive"]
                    creds = ServiceAccountCredentials.from_json_keyfile_name("service_account.json", scope)
                    gc = gspread.authorize(creds)
                    sheet = gc.open_by_key(load_config().get("sheet_id",""))
                    try:
                        ws = sheet.worksheet(report_type)
                    except Exception:
                        ws = sheet.add_worksheet(title=report_type, rows=len(df)+1, cols=len(df.columns))
                    ws.clear()
                    ws.update('A1',[df.columns.tolist()]+df.values.tolist(), value_input_option='USER_ENTERED')
                    st.success("✅ Exported to Google Sheets")

                st.download_button("💾 Download CSV", data=df.to_csv(index=False), file_name=f"{report_type}_{date.today()}.csv", mime="text/csv")

            except Exception as e:
                st.error(f"Failed: {e}")

if __name__ == "__main__":
    credential_manager()
    token_manager = QBTokenManager()
    if token_manager.handle_oauth():
        main_dashboard()
