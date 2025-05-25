# config.py - Secure Configuration Manager
import os
import json
import logging
from pathlib import Path
from typing import Dict, Any
from cryptography.fernet import Fernet, InvalidToken

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ConfigManager:
    def __init__(self):
        self.key = self._load_or_create_key()
        self.cipher = Fernet(self.key)
        self.config_path = Path("config.enc")
        self._set_file_permissions()

    def _set_file_permissions(self) -> None:
        """Set secure file permissions"""
        try:
            os.chmod(self.config_path, 0o600)
        except Exception:
            pass  # Skip if file doesn't exist yet

    def _load_or_create_key(self) -> bytes:
        """Secure key handling with file storage"""
        key_path = Path("secret.key")
        if key_path.exists():
            try:
                key = key_path.read_bytes()
                # Validate key format
                Fernet(key)  # Will raise exception if invalid
                return key
            except Exception as e:
                logger.error(f"Invalid key file: {e}")
                key_path.unlink()  # Remove invalid key

        # Generate new key
        new_key = Fernet.generate_key()
        try:
            with open(key_path, "wb") as f:
                f.write(new_key)
            os.chmod(key_path, 0o600)
            logger.info("Generated new encryption key")
            return new_key
        except Exception as e:
            logger.critical(f"Failed to create key file: {e}")
            raise

    def load_config(self) -> Dict[str, Any]:
        """Load and decrypt configuration with validation"""
        try:
            if not self.config_path.exists():
                return {}

            with open(self.config_path, "rb") as f:
                decrypted = self.cipher.decrypt(f.read()).decode()
                config = json.loads(decrypted)
                
                if not isinstance(config, dict):
                    raise ValueError("Config must be a dictionary")
                    
                return config
                
        except InvalidToken as e:
            logger.error("Invalid encryption key - config may be corrupted")
            return {}
        except json.JSONDecodeError as e:
            logger.error("Config contains invalid JSON")
            return {}
        except Exception as e:
            logger.error(f"Unexpected config load error: {e}")
            return {}

    def save_config(self, cfg: Dict[str, Any]) -> bool:
        """Atomic encrypted config save with rollback"""
        if not isinstance(cfg, dict):
            raise ValueError("Config must be a dictionary")

        temp_path = Path(f"{self.config_path}.tmp.{os.getpid()}")
        try:
            # Serialize to JSON
            json_data = json.dumps(cfg, indent=2)
            
            # Encrypt and write to temp file
            encrypted = self.cipher.encrypt(json_data.encode())
            temp_path.write_bytes(encrypted)
            
            # Atomic replace
            temp_path.replace(self.config_path)
            self._set_file_permissions()
            return True
            
        except Exception as e:
            logger.error(f"Config save failed: {e}")
            return False
        finally:
            if temp_path.exists():
                temp_path.unlink()

# Singleton instance
config_manager = ConfigManager()

# Public interface
def load_config() -> Dict[str, Any]:
    """Load the encrypted configuration"""
    return config_manager.load_config()

def save_config(cfg: Dict[str, Any]) -> None:
    """Save configuration with encryption"""
    if not config_manager.save_config(cfg):
        raise RuntimeError("Failed to save configuration")