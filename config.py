import logging
import json
import streamlit as st
from streamlit_cookies_manager import EncryptedCookieManager

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ConfigManager:
    def __init__(self):
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
            "version": "2.1.0"
        }

        # Initialize session state config
        if "config" not in st.session_state:
            st.session_state.config = self.default_config.copy()
            logger.info("Initialized st.session_state.config with default config")
        else:
            # Merge with defaults if keys are missing
            for key, value in self.default_config.items():
                if key not in st.session_state.config:
                    st.session_state.config[key] = value
            logger.info("Merged existing st.session_state.config with defaults")

    def load_config(self):
        """Return in-memory config"""
        if "config" not in st.session_state:
            st.session_state.config = self.default_config.copy()
            logger.warning("st.session_state.config was missing, initialized with default")
        logger.info("Loaded in-memory config")
        return st.session_state.config

    def save_config(self, config):
        """Save config in-memory"""
        if not isinstance(config, dict):
            raise ValueError("Config must be a dictionary")
        st.session_state.config = config
        logger.info("Config saved in-memory")

    def get(self, key, default=None):
        """Retrieve a config value"""
        if "config" not in st.session_state:
            st.session_state.config = self.default_config.copy()
            logger.warning("st.session_state.config was missing, initialized with default")
        value = st.session_state.config.get(key, default)
        logger.debug(f"Get config key: {key}, value: {value}")
        return value

    def set(self, key, value):
        """Set a config value"""
        if "config" not in st.session_state:
            st.session_state.config = self.default_config.copy()
            logger.warning("st.session_state.config was missing, initialized with default")
        st.session_state.config[key] = value
        logger.info(f"Set config key: {key} to {value}")

# Singleton instance
config_manager = ConfigManager()

# Public functions
def load_config():
    return config_manager.load_config()

def save_config(config):
    config_manager.save_config(config)
