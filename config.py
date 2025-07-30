import logging
import json
import streamlit as st
from streamlit_cookies_manager import EncryptedCookieManager

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ConfigManager:
    def __init__(self, cookie_manager):
        self.config_cookies = cookie_manager
        if not self.config_cookies.ready():
            logger.error("Config cookies not ready")
            raise RuntimeError("Config cookies initialization failed")

        # Default configuration
        self.default_config = {
            "qb_client_id": "",
            "qb_client_secret": "",
            "redirect_uri": "https://zugabooks.onrender.com",
            "realm_id": "9341454953961084",
            "access_token": None,
            "refresh_token": None,
            "expires_at": 0,
            "google_sheets": {"sheet_id": "1ZVOs-WWFtfUfwrBwyMa18IFvrB_4YWZlACmFJ3ZGMV8"},
            "version": "1.3.8"
        }

        # Initialize session state config
        if "config" not in st.session_state:
            st.session_state.config = self.load_config_from_cookie() or self.default_config
            logger.info("Initialized st.session_state.config with default or cookie config")
        else:
            # Merge with defaults if keys are missing
            for key, value in self.default_config.items():
                if key not in st.session_state.config:
                    st.session_state.config[key] = value
            logger.info("Merged existing st.session_state.config with defaults")

        logger.info("Initialized in-memory ConfigManager")

    def load_config_from_cookie(self):
        """Load config from encrypted cookie"""
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
        """Save config to encrypted cookie"""
        try:
            config_str = json.dumps(config)
            self.config_cookies["config"] = config_str
            self.config_cookies.save()
            logger.info("Saved config to cookie")
        except Exception as e:
            logger.error(f"Failed to save config to cookie: {e}")

    def load_config(self):
        """Return in-memory config"""
        if "config" not in st.session_state:
            st.session_state.config = self.default_config
            logger.warning("st.session_state.config was missing, initialized with default")
        logger.info("Loaded in-memory config")
        return st.session_state.config

    def save_config(self, config):
        """Save config in-memory and to cookie"""
        if not isinstance(config, dict):
            raise ValueError("Config must be a dictionary")
        st.session_state.config = config
        self.save_config_to_cookie(config)
        logger.info("Config saved in-memory and to cookie")

    def get(self, key, default=None):
        """Retrieve a config value"""
        if "config" not in st.session_state:
            st.session_state.config = self.default_config
            logger.warning("st.session_state.config was missing, initialized with default")
        value = st.session_state.config.get(key, default)
        logger.debug(f"Get config key: {key}, value: {value}")
        return value

    def set(self, key, value):
        """Set a config value"""
        if "config" not in st.session_state:
            st.session_state.config = self.default_config
            logger.warning("st.session_state.config was missing, initialized with default")
        st.session_state.config[key] = value
        self.save_config(st.session_state.config)
        logger.info(f"Set config key: {key} to {value}")

# Singleton instance
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
