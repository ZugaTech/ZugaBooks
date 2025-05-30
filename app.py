import streamlit as st

# ————————————————————————————————————————————————
# MUST be the very first Streamlit call
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
# Cookie + “remember me” setup
COOKIE_SECRET = os.getenv("COOKIE_SECRET") or st.secrets.get("general", {}).get("COOKIE_SECRET")
if not COOKIE_SECRET:
    st.error("🔒 Missing COOKIE_SECRET")
    st.stop()
cookies = EncryptedCookieManager(prefix="zugabooks", password=COOKIE_SECRET)
if not cookies.ready():
    st.stop()

# ————————————————————————————————————————————————
# Password-gate (only once)
APP_PASSWORD = os.getenv("APP_PASSWORD") or st.secrets.get("APP_PASSWORD", "")
if not APP_PASSWORD:
    st.error("🔒 Missing APP_PASSWORD")
    st.stop()

def password_gate():
    last_ts = cookies.get("last_auth_ts")
    now = int(time.time())
    if last_ts and now - int(last_ts) < 24*3600:
        return

    st.sidebar.title("🔐 Login Required")
    pw = st.sidebar.text_input("Enter Access Password", type="password", key="password_gate")
    if "authenticated" not in st.session_state:
        st.session_state.authenticated = False

    if pw == APP_PASSWORD:
        st.session_state.authenticated = True
        cookies["last_auth_ts"] = str(now)
        cookies.save()
        st.sidebar.success("✅ Access granted — valid for 24h")
    else:
        if pw:
            st.sidebar.error("❌ Incorrect")
        st.stop()

password_gate()

# ————————————————————————————————————————————————
# Sidebar: credentials manager
def credential_manager():
    cfg = load_config()
    with st.sidebar.expander("🔧 Credentials & Settings", expanded=True):
        st.markdown("### QuickBooks & Google Sheets")
        new_cid = st.text_input("QuickBooks Client ID", value=cfg.get("qb_client_id",""), type="password", key="qb_cid")
        new_secret = st.text_input("QuickBooks Client Secret", value=cfg.get("qb_client_secret",""), type="password", key="qb_secret")
        new_redirect = st.text_input("QuickBooks Redirect URI", value=cfg.get("redirect_uri",""), key="qb_redirect")
        new_realm = st.text_input("QuickBooks Realm ID", value=cfg.get("realm_id",""), type="password", key="qb_realm")
        new_sheet = st.text_input("Google Sheet ID", value=cfg.get("sheet_id",""), key="sheet_id")
        sa_file = st.file_uploader("Service Account JSON", type=["json"], key="sa_file")
        if st.button("💾 Save All Credentials", key="save_creds"):
            updated = False
            for k,v in [
                ("qb_client_id", new_cid),
                ("qb_client_secret", new_secret),
                ("redirect_uri", new_redirect),
                ("realm_id", new_realm),
                ("sheet_id", new_sheet)
            ]:
                if v and v != cfg.get(k):
                    cfg[k] = v; updated = True
            if sa_file:
                with open("service_account.json","wb") as f:
                    f.write(sa_file.getbuffer())
                updated = True
            if updated:
                save_config(cfg)
                st.success("✅ Saved — reload to apply")
                st.experimental_rerun()
            else:
                st.warning("Nothing changed")

credential_manager()

# ————————————————————————————————————————————————
# … your imports, password_gate(), credential_manager() … 

credential_manager()

# ← Insert the Reset button here:
if st.sidebar.button("🔄 Reset QuickBooks Authorization", key="reset_qb_auth"):
    st.session_state.pop("tokens", None)
    st.session_state.qb_auth_phase = "init"
    cfg = load_config()
    for k in ("access_token","refresh_token","expires_at","realm_id"):
        cfg.pop(k, None)
    save_config(cfg)
    st.experimental_rerun()
    
# OAuth + tokens
class QBTokenManager:
    def __init__(self):
        self.cfg = load_config()
        for field in ("qb_client_id","qb_client_secret","redirect_uri"):
            if not self.cfg.get(field):
                st.error(f"❌ Missing {field} in config")
                st.stop()
        self.auth_client = AuthClient(
            client_id=self.cfg["qb_client_id"],
            client_secret=self.cfg["qb_client_secret"],
            environment="production",
            redirect_uri=self.cfg["redirect_uri"]
        )

        # init session state:
        if "qb_auth_phase" not in st.session_state:
            st.session_state.qb_auth_phase = "init"
        if "tokens" not in st.session_state:
            st.session_state.tokens = {
                "access_token": self.cfg.get("access_token"),
                "refresh_token": self.cfg.get("refresh_token"),
                "expires_at": self.cfg.get("expires_at", 0)
            }

    def handle_oauth(self):
        # debug expander
        with st.expander("Auth State", expanded=False):
            st.json({
                "phase": st.session_state.qb_auth_phase,
                "tokens": {
                    k: ("****" if "token" in k else v)
                    for k,v in st.session_state.tokens.items()
                }
            })

        # 1) if we already have a valid token → done
        if self._has_valid_tokens():
            return True

        # 2) state machine:
        if st.session_state.qb_auth_phase == "init":
            self._start_authorization()
        elif st.session_state.qb_auth_phase == "code_exchange":
            self._exchange_authorization_code()

        # if we get here, we’re waiting for user action
        st.info("🔒 QuickBooks auth in progress…")
        st.stop()

    def _has_valid_tokens(self):
        t = st.session_state.tokens
        if not t.get("access_token"):
            return False
        if time.time() > t.get("expires_at",0):
            try:
                new = self.auth_client.refresh(t["refresh_token"])
                st.session_state.tokens = {
                    "access_token": new.access_token,
                    "refresh_token": new.refresh_token,
                    "expires_at": time.time() + new.expires_in
                }
                self.cfg.update(st.session_state.tokens)
                save_config(self.cfg)
                st.session_state.qb_auth_phase = "complete"
                st.success("✅ Token refreshed!")
                time.sleep(1)
                return True
            except Exception:
                st.warning("🔄 Refresh failed, please re-auth")
                st.session_state.tokens = {}
                return False
        return True

    def _start_authorization(self):
        params = st.experimental_get_query_params()
        if "code" in params:
            st.session_state["qb_code"] = params["code"][0]
            st.session_state.qb_auth_phase = "code_exchange"
            st.experimental_set_query_params()  # clear URL
            st.rerun()

        st.markdown("## 🔑 QuickBooks Authorization")
        url = self.auth_client.get_authorization_url([Scopes.ACCOUNTING])
        st.markdown(f"[Click to authorize →]({url})", unsafe_allow_html=True)
        st.info(f"Redirect URI: `{self.cfg['redirect_uri']}`")

    def _exchange_authorization_code(self):
        code = st.session_state.get("qb_code")
        if not code:
            st.error("❌ No code in session")
            st.session_state.qb_auth_phase = "init"
            return

        try:
            clean = code.split("code=")[-1].split("&")[0]
            tok = self.auth_client.get_bearer_token(clean)
            st.session_state.tokens = {
                "access_token": tok["access_token"],
                "refresh_token": tok["refresh_token"],
                "expires_at": time.time() + tok.get("expires_in",3600)
            }
            self.cfg.update(st.session_state.tokens)
            if "realmId" in tok:
                self.cfg["realm_id"] = tok["realmId"]
            save_config(self.cfg)
            st.session_state.qb_auth_phase = "complete"
            st.success("✅ Authorized! loading…")
            time.sleep(1)
        except AuthClientError as e:
            st.error(f"🔴 API Error: {e.status_code} – {e.content}")
            st.session_state.qb_auth_phase = "init"
        except Exception as e:
            st.error(f"🔴 Auth failed: {e}")
            st.session_state.qb_auth_phase = "init"

# ————————————————————————————————————————————————
def main_dashboard():
    st.title("📊 Financial Dashboard")
    today = date.today()
    c1,c2 = st.columns(2)
    with c1:
        start = st.date_input("Start Date", today - timedelta(days=30), key="start")
    with c2:
        end = st.date_input("End Date", today, key="end")
    if start> end:
        st.error("End date must be after start"); st.stop()

    rpt = st.selectbox("Report Type", ["ProfitAndLoss","BalanceSheet","TransactionList"], key="rpt")

    # vendor→category CSV (optional)
    m = st.sidebar.file_uploader("CSV: Vendor→Category", type=["csv"], key="map")
    cat = {}
    if m:
        dfm = pd.read_csv(m)
        if {'Vendor','Category'}.issubset(dfm.columns):
            cat = dict(zip(dfm['Vendor'], dfm['Category']))
        else:
            st.sidebar.warning("CSV must contain Vendor + Category")

    if st.button("🔄 Generate Report", key="gen"):
        with st.spinner("Fetching…"):
            try:
                qb = QuickBooks(
                    auth_client=token_manager.auth_client,
                    access_token=st.session_state.tokens["access_token"],
                    refresh_token=st.session_state.tokens["refresh_token"],
                    company_id=token_manager.cfg.get("realm_id","")
                )
                params = {"start_date":start.strftime("%Y-%m-%d"), "end_date":end.strftime("%Y-%m-%d")}
                rep = qb.get_report(report_name=rpt, params=params)
                df = get_report_dataframe(rep.get("Rows",{}).get("Row",[]), rpt)
                if cat:
                    df = apply_custom_categories(df, m)
                st.dataframe(df, use_container_width=True)

                if st.button("📤 Export to Sheets", key="exp"):
                    scope = ["https://spreadsheets.google.com/feeds","https://www.googleapis.com/auth/drive"]
                    creds = ServiceAccountCredentials.from_json_keyfile_name("service_account.json", scope)
                    gc = gspread.authorize(creds)
                    sheet = gc.open_by_key(load_config().get("sheet_id",""))
                    try: ws = sheet.worksheet(rpt)
                    except: ws = sheet.add_worksheet(title=rpt, rows=len(df)+1, cols=len(df.columns))
                    ws.clear()
                    ws.update("A1",[df.columns.tolist()]+df.values.tolist(), value_input_option="USER_ENTERED")
                    st.success("✅ Exported")
                st.download_button("💾 CSV", data=df.to_csv(index=False), file_name=f"{rpt}_{today}.csv", key="dl")

            except Exception as e:
                st.error(f"❌ {e}")

# ————————————————————————————————————————————————
if __name__=="__main__":
    token_manager = QBTokenManager()
    if token_manager.handle_oauth():
        main_dashboard()
