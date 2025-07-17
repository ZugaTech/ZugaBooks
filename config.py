# Version: 1.3.5 - Enhanced initialization and logging
import logging
import json
import streamlit as st
from streamlit_cookies_manager import EncryptedCookieManager

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ConfigManager:
    def __init__(self, cookie_manager):
        self.config_cookies = cookie_manager
        if not self.config_cookies.ready():
            logger.error("Config cookies not ready")
            raise RuntimeError("Config cookies initialization failed")
        
        self.default_config = {
            "qb_client_id": "",
            "qb_client_secret": "",
            "redirect_uri": "https://zugabooks.onrender.com/",
            "realm_id": "9341454953961084",
            "access_token": None,
            "refresh_token": None,
            "expires_at": 0,
            "google_sheets": {
                "sheet_id": "1ZVOs-WWFtfUfwrBwyMa18IFvrB_4YWZlACmFJ3ZGMV8"
            },
            "version": "1.3.5"
        }
        if "config" not in st.session_state:
            st.session_state.config = self.load_config_from_cookie() or self.default_config
        logger.info("Initialized in-memory ConfigManager")

    def load_config_from_cookie(self):
        if "config" in self.config_cookies:
            try:
                config_str = self.config_cookies["config"]
                config = json.loads(config_str)
                logger.info("Loaded config from cookie")
                return config
            except Exception as e:
                logger.error(f"Failed to load config from cookie: {e}")
        return None

    def save_config_to_cookie(self, config):
        try:
            config_str = json.dumps(config)
            self.config_cookies["config"] = config_str
            self.config_cookies.save()
            logger.info("Saved config to cookie")
        except Exception as e:
            logger.error(f"Failed to save config to cookie: {e}")

    def load_config(self):
        logger.info("Loaded in-memory config")
        return st.session_state.config

    def save_config(self, config):
        if not isinstance(config, dict):
            raise ValueError("Config must be a dictionary")
        st.session_state.config = config
        self.save_config_to_cookie(config)
        logger.info("Config saved in-memory and to cookie")

    def get(self, key, default=None):
        return st.session_state.config.get(key, default)

    def set(self, key, value):
        st.session_state.config[key] = value
        self.save_config(st.session_state.config)
        logger.info(f"Set config key: {key}")

# Singleton instance
config_manager = None

def initialize(cookie_manager):
    """Initialize ConfigManager and track in session state"""
    global config_manager
    if "config_initialized" not in st.session_state:
        st.session_state.config_initialized = False
    
    if not st.session_state.config_initialized:
        config_manager = ConfigManager(cookie_manager)
        st.session_state.config_initialized = True
        logger.info("ConfigManager initialized with cookie_manager")
    else:
        logger.debug("ConfigManager already initialized")

def load_config():
    global config_manager
    if config_manager is None:
        raise RuntimeError("ConfigManager not initialized. Ensure config.initialize() is called in app.py.")
    return config_manager.load_config()

def save_config(config):
    global config_manager
    if config_manager is None:
        raise RuntimeError("ConfigManager not initialized. Ensure config.initialize() is called in app.py.")
    config_manager.save_config(config)
    config_manager.save_config(config)
