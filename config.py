# config.py - Enterprise-Grade Configuration Manager
import os
import json
import logging
import hashlib
from pathlib import Path
from typing import Dict, Any, Optional, Tuple
from cryptography.fernet import Fernet, InvalidToken
from datetime import datetime, timedelta
import streamlit as st
from streamlit_cookies_manager import EncryptedCookieManager

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Cookie setup (must match app.py)
COOKIE_SECRET = st.secrets.get("general", {}).get("COOKIE_SECRET", os.getenv("COOKIE_SECRET"))
if not COOKIE_SECRET:
    logger.error("Missing COOKIE_SECRET")
    raise ValueError("COOKIE_SECRET must be set in environment or secrets")

config_cookies = EncryptedCookieManager(prefix="zugabooks_config", password=COOKIE_SECRET)
if not config_cookies.ready():
    logger.error("Config cookies not ready")
    raise RuntimeError("Config cookies initialization failed")

class ConfigManager:
    def __init__(self):
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
            "version": "1.3.0"
        }
        # Load from cookie or use default
        if "config" not in st.session_state:
            st.session_state.config = self.load_config_from_cookie() or self.default_config
        logger.info("Initialized in-memory ConfigManager")
        print("Initialized in-memory ConfigManager")  # Debug

    def load_config_from_cookie(self):
        """Load configuration from encrypted cookie"""
        if "config" in config_cookies:
            try:
                config_str = config_cookies["config"]
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
            config_cookies["config"] = config_str
            config_cookies.save()
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

# Singleton instance
config_manager = ConfigManager()

# Public functions
def load_config():
    return config_manager.load_config()

def save_config(config):
    config_manager.save_config(config)
