# Version: 1.3.3 - Pass EncryptedCookieManager from app.py to avoid DuplicateWidgetID
import logging
import json
import os
import streamlit as st
from streamlit_cookies_manager import EncryptedCookieManager

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ConfigManager:
    def __init__(self, cookie_manager):
        # Store the passed cookie manager
        self.config_cookies = cookie_manager
        if not self.config_cookies.ready():
            logger.error("Config cookies not ready")
            raise RuntimeError("Config cookies initialization failed")

        # Initialize with defaults from config.json
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
            "version": "1.3.3"
        }
        # Load from cookie or use default
        if "config" not in st.session_state:
            st.session_state.config = self.load_config_from_cookie() or self.default_config
        logger.info("Initialized in-memory ConfigManager")
        print("Initialized in-memory ConfigManager")  # Debug

    def load_config_from_cookie(self):
        """Load configuration from encrypted cookie"""
        if "config" in self.config_cookies:
            try:
                config_str = self.config_cookies["config"]
                config = json.loads(config_str)
                logger.info("Loaded config from cookie")
                print("Loaded config from cookie")  # Debug
                return config
            except Exception as e:
                logger.error(f"Failed to load config from cookie: {e}")
                print(f"Failed to load config from cookie: {e}")  # Debug
        return None

    def save_config_to_cookie(self, config):
        """Save configuration to encrypted cookie"""
        try:
            config_str = json.dumps(config)
            self.config_cookies["config"] = config_str
            self.config_cookies.save()
            logger.info("Saved config to cookie")
            print("Saved config to cookie")  # Debug
        except Exception as e:
            logger.error(f"Failed to save config to cookie: {e}")
            print(f"Failed to save config to cookie: {e}")  # Debug

    def load_config(self):
        """Return in-memory config from session state"""
        logger.info("Loaded in-memory config")
        print("Loaded in-memory config")  # Debug
        return st.session_state.config

    def save_config(self, config):
        """Save config in-memory and to cookie"""
        if not isinstance(config, dict):
            raise ValueError("Config must be a dictionary")
        st.session_state.config = config
        self.save_config_to_cookie(config)
        logger.info("Config saved in-memory and to cookie")
        print("Config saved in-memory and to cookie")  # Debug

    def get(self, key, default=None):
        return st.session_state.config.get(key, default)

    def set(self, key, value):
        st.session_state.config[key] = value
        self.save_config(st.session_state.config)
        logger.info(f"Set config key: {key}")
        print(f"Set config key: {key}")  # Debug

# Singleton instance (will be initialized in app.py)
config_manager = None

# Public functions
def load_config():
    if config_manager is None:
        raise RuntimeError("ConfigManager not initialized")
    return config_manager.load_config()

def save_config(config):
    if config_manager is None:
        raise RuntimeError("ConfigManager not initialized")
    config_manager.save_config(config)
