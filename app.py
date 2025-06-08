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
from intuitlib.exceptions import AuthClientError

from utils import get_report_dataframe, apply_custom_categories
from config import load_config, save_config
from streamlit_cookies_manager import EncryptedCookieManager

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
# Password-gate (once per 24h)
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
            help="From your Google Sheets URL (…/d/[THIS_IS_SHEET_ID]/edit)",
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
                cfg.setdefault("google_sheets", {})["sheet_id"] = new_sheet
                updated = True
            # Service Account File
            if sa_file:
                with open("service_account.json", "wb") as f:
                    f.write(sa_file.getbuffer())
                updated = True
            if updated:
                save_config(cfg, force_plaintext=True)
                st.success("✅ Configuration saved successfully!")
                st.balloons()
                from streamlit import cache_data
                cache_data.clear()
                st.experimental_rerun()
            else:
                st.warning("⚠️ No changes detected")

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
                if Path("config.enc").exists() else "Never"
            )
        })

credential_manager()

# ————————————————————————————————————————————————
# ── REPLACED QBTokenManager ───────────────────────────────────────────────────
class QBTokenManager:
    def __init__(self):
        self.cfg = load_config()

        required = {
            "qb_client_id":     "Client ID (Intuit Developer Portal)",
            "qb_client_secret": "Client Secret (Intuit Developer Portal)",
            "redirect_uri":     "Redirect URI (must match exactly)"
        }
        missing = [f"{k} — {v}" for k, v in required.items() if not self.cfg.get(k)]
        if missing:
            st.error("❌ Missing configuration:\n• " + "\n• ".join(missing))
            st.stop()

        self.auth_client = AuthClient(
            client_id=self.cfg["qb_client_id"],
            client_secret=self.cfg["qb_client_secret"],
            environment="production",  # or "sandbox"
            redirect_uri=self.cfg["redirect_uri"]
        )

        st.session_state.setdefault("tokens", {
            "access_token":  self.cfg.get("access_token"),
            "refresh_token": self.cfg.get("refresh_token"),
            "expires_at":    self.cfg.get("expires_at", 0)
        })

    def _refresh_token(self) -> bool:
        rt = st.session_state.tokens.get("refresh_token")
        if not rt:
            return False
        try:
            self.auth_client.refresh_token = rt
            new = self.auth_client.refresh()
            if not getattr(new, "access_token", None):
                return False
            st.session_state.tokens = {
                "access_token":  new.access_token,
                "refresh_token": new.refresh_token,
                "expires_at":    time.time() + new.expires_in
            }
            self.cfg.update(st.session_state.tokens)
            save_config(self.cfg)
            return True
        except Exception:
            return False

    def handle_oauth(self) -> bool:
        tokens = st.session_state.tokens
        # 1) still valid?
        if tokens.get("access_token") and time.time() < tokens.get("expires_at", 0):
            return True
        # 2) try refresh
        if tokens.get("refresh_token") and self._refresh_token():
            st.success("✅ Token refreshed!")
            time.sleep(1)
            st.rerun()
            return True
        # 3) manual authorize
        return self._authorize()

    def _authorize(self) -> bool:
        st.markdown("## 🔑 QuickBooks Authorization")
        auth_url = self.auth_client.get_authorization_url([Scopes.ACCOUNTING])
        st.markdown(f"""
            1. [Click here to authorize]({auth_url})
            2. Log into QuickBooks and approve access
            3. Copy the `code=` value from the redirect URL
        """)
        st.info(f"**Redirect URI:** `{self.auth_client.redirect_uri}`")
        st.warning("⚠️ Codes expire in 5 minutes!")

        code = st.text_input("Paste authorization code here:", key="qb_auth_code")
        if not code:
            st.stop()
        clean = code.strip().split("code=")[-1].split("&")[0]
        st.write(f"Using code: `{clean[:10]}…`")  # debug

        
        try:
    with st.spinner("Exchanging code for tokens…"):
        resp = self.auth_client.get_bearer_token(clean)
        st.write("⚠️ Token Response (debug):", resp)

    # Safely extract values whether resp is dict or object
    at = resp.get("access_token") if isinstance(resp, dict) else getattr(resp, "access_token", None)
    rt = resp.get("refresh_token") if isinstance(resp, dict) else getattr(resp, "refresh_token", None)
    ei = resp.get("expires_in")    if isinstance(resp, dict) else getattr(resp, "expires_in", None)

    # Validate access token
    if not at:
        st.error(f"🔴 No access_token returned.\nFull response: `{resp}`")
        st.stop()

    # Save to session state
    st.session_state.tokens = {
        "access_token": at,
        "refresh_token": rt,
        "expires_at": time.time() + (ei or 3600)
    }

    # Save realm ID if present
    realm = (
        resp.get("realmId") if isinstance(resp, dict)
        else getattr(resp, "realm_id", None)
    )
    if realm:
        self.cfg["realm_id"] = realm

    # Persist config and rerun
    self.cfg.update(st.session_state.tokens)
    save_config(self.cfg)

    st.success("✅ Authorization successful!")
    time.sleep(1)
    st.rerun()

except AuthClientError as e:
    st.error(f"🔴 QuickBooks API Error {e.status_code}:\n{e.content}")
    st.stop()

except Exception as e:
    st.error(f"🔴 Authorization failed:\n{e}")
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
            st.sidebar.error(f"Error reading CSV: {e}")

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
                    "end_date":   end.strftime("%Y-%m-%d")
                }
                rep = qb.get_report(report_name=rpt, params=params)
                df = get_report_dataframe(rep.get("Rows", {}).get("Row", []), rpt)
                if cat_map:
                    df = apply_custom_categories(df, m)
                st.subheader(f"{rpt} Report")
                st.dataframe(df, use_container_width=True)

                if st.button("📤 Export to Google Sheets", key="exp"):
                    cfg2 = load_config()
                    sheet_id = cfg2.get("google_sheets", {}).get("sheet_id", "")
                    if not sheet_id:
                        st.error("❌ Google Sheet ID not configured")
                        return
                    scope = ["https://spreadsheets.google.com/feeds","https://www.googleapis.com/auth/drive"]
                    creds = ServiceAccountCredentials.from_json_keyfile_name("service_account.json", scope)
                    gc = gspread.authorize(creds)
                    sheet = gc.open_by_key(sheet_id)
                    try:
                        ws = sheet.worksheet(rpt)
                    except gspread.exceptions.WorksheetNotFound:
                        ws = sheet.add_worksheet(title=rpt, rows=len(df)+1, cols=len(df.columns))
                    ws.clear()
                    ws.update("A1", [df.columns.tolist()] + df.values.tolist(), value_input_option="USER_ENTERED")
                    st.success("✅ Exported to Google Sheets!")

                st.download_button("💾 Download CSV", data=df.to_csv(index=False),
                                   file_name=f"{rpt}_{today}.csv", mime="text/csv", key="dl")

            except Exception as e:
                st.error(f"❌ Report generation failed: {e}")

# ————————————————————————————————————————————————
if __name__ == "__main__":
    # Reset QuickBooks auth
    if st.sidebar.button("🔄 Reset QuickBooks Authorization", key="reset_qb_auth"):
        st.session_state.pop("tokens", None)
        cfg3 = load_config()
        for k in ("access_token","refresh_token","expires_at","realm_id"):
            cfg3.pop(k, None)
        save_config(cfg3)
        st.success("Auth reset—please reauthorize")
        time.sleep(1)
        st.rerun()

    token_manager = QBTokenManager()

    # Connection status
    if st.session_state.tokens.get("access_token"):
        st.sidebar.success("✅ Connected to QuickBooks")
    else:
        st.sidebar.warning("🔴 Not connected to QuickBooks")

    if token_manager.handle_oauth():
        main_dashboard()

    # DEBUG MODE (optional) …
