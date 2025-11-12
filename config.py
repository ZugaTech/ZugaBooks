import streamlit as st
import logging

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ConfigManager:
    """
    A simplified ConfigManager that uses Streamlit's session_state for in-memory
    configuration management, perfect for a self-contained demo app.
    """
    def __init__(self):
        # Default configuration, loaded once at the start.
        self.default_config = {
            "version": "2.1.0-demo",
            "app_name": "ZugaBooks Demo",
            "google_sheets": {"sheet_id": "demo_sheet_id_placeholder"},
            "quickbooks": {"client_id": "demo_client_id_placeholder"}
        }

        # Initialize session state config if it doesn't exist.
        if "config" not in st.session_state:
            st.session_state.config = self.default_config.copy()
            logger.info("Initialized st.session_state.config with default demo config.")

    def load_config(self):
        """Returns the current in-memory configuration dictionary."""
        return st.session_state.get("config", self.default_config.copy())

    def save_config(self, new_config):
        """
        Updates the in-memory configuration.
        Args:
            new_config (dict): The dictionary to replace the current config with.
        """
        if not isinstance(new_config, dict):
            raise ValueError("Configuration must be a dictionary.")
        st.session_state.config = new_config
        logger.info("Configuration saved in-memory (session_state).")

    def get(self, key, default=None):
        """
        Retrieves a specific value from the configuration.
        Args:
            key (str): The configuration key to retrieve.
            default: The value to return if the key is not found.
        Returns:
            The value associated with the key, or the default.
        """
        config = self.load_config()
        return config.get(key, default)

    def set(self, key, value):
        """
        Sets a specific key-value pair in the configuration.
        Args:
            key (str): The key to set.
            value: The value to assign to the key.
        """
        config = self.load_config()
        config[key] = value
        self.save_config(config)
        logger.info(f"Set config key '{key}' in-memory.")


config_manager = ConfigManager()
