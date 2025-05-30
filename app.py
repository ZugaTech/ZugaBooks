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

# now safe to import the cookie manager
from streamlit_cookies_manager import EncryptedCookieManager

# ————————————————————————————————————————————————
# Cookie manager setup (remember-me for 24h)
COOKIE_SECRET = st.secrets["general"]["COOKIE_SECRET"]
cookies = EncryptedCookieManager(
    prefix="zugabooks",
    password=COOKIE_SECRET
)
if not cookies.ready():
    st.stop()

# ————————————————————————————————————————————————
# Secure App Password
APP_PASSWORD = os.getenv("APP_PASSWORD", "")
if not APP_PASSWORD:
    try:
        APP_PASSWORD = st.secrets["APP_PASSWORD"]
    except KeyError:
        APP_PASSWORD = ""

def password_gate():
    last = cookies.get("last_auth_ts")
    now = int(time.time())
    if last and now - int(last) < 24 * 3600:
        return  # still valid

    st.sidebar.title("🔐 Login Required")
    pw = st.sidebar.text_input("Enter Access Password", type="password", key="password_gate")
    if "authenticated" not in st.session_state:
        st.session_state.authenticated = False

    if pw and APP_PASSWORD and pw == APP_PASSWORD:
        st.session_state.authenticated = True
        cookies["last_auth_ts"] = str(now)
        cookies.save()
        st.sidebar.success("✅ Access granted — you won't be asked again for 24h")
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
class QBTokenManager:
    def __init__(self):
        self.cfg = load_config()
        if not all([self.cfg.get("qb_client_id"),
                    self.cfg.get("qb_client_secret"),
                    self.cfg.get("redirect_uri")]):
            st.error("❌ Please set QuickBooks credentials & redirect URI")
            st.stop()
        self.auth_client = AuthClient(
            client_id=self.cfg["qb_client_id"],
            client_secret=self.cfg["qb_client_secret"],
            environment="production",
            redirect_uri=self.cfg["redirect_uri"]
        )

    def handle_oauth(self):
        if "tokens" not in st.session_state:
            toks = {}
            if self.cfg.get("access_token"):
                toks = dict(
                    access_token=self.cfg["access_token"],
                    refresh_token=self.cfg["refresh_token"],
                    expires_at=self.cfg.get("expires_at",0)
                )
            st.session_state.tokens = toks

        toks = st.session_state.tokens

        # 1) auto-refresh if expired
        if toks.get("access_token"):
            if time.time() > toks.get("expires_at",0):
                try:
                    self.auth_client.refresh_token = toks["refresh_token"]
                    new = self.auth_client.refresh()
                    if not hasattr(new,"access_token"):
                        raise ValueError("Bad refresh response")
                    toks = dict(
                        access_token=new.access_token,
                        refresh_token=new.refresh_token,
                        expires_at=time.time()+new.expires_in
                    )
                    st.session_state.tokens = toks
                    self.cfg.update(toks)
                    save_config(self.cfg)
                except Exception:
                    st.warning("🔄 Session expired—please re-authorize")
                    st.session_state.tokens = {}
                    return False
            return True

        # 2) grab code from URL
        params = st.experimental_get_query_params()
        if params.get("code"):
            st.session_state["qb_code"] = params["code"][0]

        # 3) prompt for authorization
        st.markdown("## Authorize QuickBooks")
        auth_url = self.auth_client.get_authorization_url([Scopes.ACCOUNTING])
        st.markdown(f"[Authorize →]({auth_url})", unsafe_allow_html=True)

        code = st.text_input("OAuth Code",
                             value=st.session_state.get("qb_code",""),
                             key="qb_auth_code")
        if not code:
            st.stop()

        # 4) exchange for tokens
        try:
            clean = code.strip().split("code=")[-1].split("&")[0]
            tok = self.auth_client.get_bearer_token(clean)
            if not tok or "access_token" not in tok:
                raise ValueError("No tokens returned")
            toks = dict(
                access_token=tok["access_token"],
                refresh_token=tok["refresh_token"],
                expires_at=time.time()+tok.get("expires_in",3600)
            )
            st.session_state.tokens = toks
            self.cfg.update(toks)
            if "realmId" in tok:
                self.cfg["realm_id"] = tok["realmId"]
            save_config(self.cfg)
            st.success("✅ Connected!")
            st.experimental_rerun()
        except AuthClientError as e:
            st.error(f"🔴 QuickBooks API Error: {e.status_code} – {e.content}")
            st.stop()
        except Exception as e:
            st.error(f"🔴 Authorization failed: {e}")
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
