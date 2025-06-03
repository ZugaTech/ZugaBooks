# config.py - Enterprise-Grade Configuration Manager
import os
import json
import logging
import hashlib
from pathlib import Path
from typing import Dict, Any, Optional, Tuple
from cryptography.fernet import Fernet, InvalidToken
from datetime import datetime, timedelta

# Security Constants
CONFIG_VERSION = "2.3"
MIN_PYTHON_VERSION = (3, 8)
ALLOWED_ENVIRONMENTS = {"production", "sandbox", "development"}

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class ConfigManager:
    def __init__(self):
        self._validate_python_version()
        self.key = self._load_or_create_key()
        self.cipher = Fernet(self.key)
        self.config_path = Path("config.enc")
        self.plain_config_path = Path("config.json")
        self.backup_path = Path("config.backup.enc")
        self._ensure_secure_paths()

    def _validate_python_version(self):
        """Ensure minimum Python version for security"""
        import sys
        if sys.version_info < MIN_PYTHON_VERSION:
            raise RuntimeError(
                f"Python {MIN_PYTHON_VERSION[0]}.{MIN_PYTHON_VERSION[1]}+ required"
            )

    def _ensure_secure_paths(self):
        """Set secure permissions and validate paths"""
        secure_paths = [
            self.config_path,
            self.plain_config_path,
            self.backup_path,
            Path("secret.key")
        ]
        
        for path in secure_paths:
            try:
                if path.exists():
                    path.chmod(0o600)
            except Exception as e:
                logger.warning(f"Could not secure {path}: {str(e)}")

    def _load_or_create_key(self) -> bytes:
        """Enterprise-grade key management with rotation support"""
        key_path = Path("secret.key")
        
        # Key validation checks
        def is_valid_key(key: bytes) -> bool:
            try:
                Fernet(key)
                return len(key) == 44  # Fernet key length check
            except (ValueError, InvalidToken):
                return False

        # Try loading existing key
        if key_path.exists():
            try:
                key = key_path.read_bytes()
                if is_valid_key(key):
                    return key
                logger.warning("Invalid key detected - generating replacement")
            except Exception as e:
                logger.error(f"Key read failed: {str(e)}")

        # Generate and save new key
        new_key = Fernet.generate_key()
        try:
            # Atomic write with backup
            temp_path = key_path.with_suffix(f".tmp.{os.getpid()}")
            temp_path.write_bytes(new_key)
            temp_path.chmod(0o600)
            temp_path.replace(key_path)
            logger.info("Generated new encryption key")
            return new_key
        except Exception as e:
            logger.critical(f"Key generation failed: {str(e)}")
            raise RuntimeError("Cannot initialize without valid key")

    def load_config(self, *, force_plaintext: bool = False) -> Dict[str, Any]:
        """
        Load configuration with multiple fallback layers
        Args:
            force_plaintext: Bypass encryption (for emergency recovery)
        Returns:
            Validated configuration dictionary
        Raises:
            RuntimeError: For unrecoverable failures
        """
        try:
            # Emergency recovery mode
            if force_plaintext:
                config = self._load_plain_config()
                if config:
                    logger.critical("OPERATING IN PLAINTEXT RECOVERY MODE")
                    return config
                raise RuntimeError("No valid plaintext config available")

            # Normal encrypted load
            if self.config_path.exists():
                config = self._load_encrypted_config()
                if config:
                    return config

            # Fallback to backup
            if self.backup_path.exists():
                logger.warning("Falling back to backup config")
                config = self._load_encrypted_config(self.backup_path)
                if config:
                    self._atomic_save(self.config_path, self.cipher.encrypt(
                        json.dumps(config).encode()
                    ))
                    return config

            # Final fallback to plaintext
            if self.plain_config_path.exists():
                logger.warning("Falling back to plaintext config")
                config = self._load_plain_config()
                if config:
                    self.save_config(config)  # Re-encrypt if valid
                    return config

            return self._create_default_config()

        except Exception as e:
            logger.error(f"Config load failed: {str(e)}")
            raise RuntimeError("Configuration system failure")

    def _load_encrypted_config(self, path: Optional[Path] = None) -> Dict[str, Any]:
        """Secure encrypted config loader with validation"""
        target_path = path or self.config_path
        try:
            with open(target_path, "rb") as f:
                encrypted = f.read()
                decrypted = self.cipher.decrypt(encrypted).decode()
                config = json.loads(decrypted)
                return self._validate_config(config)
        except InvalidToken:
            logger.error("Invalid encryption key - possible tampering")
        except json.JSONDecodeError:
            logger.error("Config contains invalid JSON")
        except Exception as e:
            logger.error(f"Unexpected decrypt error: {str(e)}")
        return {}

    def _load_plain_config(self) -> Dict[str, Any]:
        """Secure plaintext config loader"""
        try:
            with open(self.plain_config_path, "r") as f:
                config = json.load(f)
                return self._validate_config(config)
        except Exception as e:
            logger.error(f"Plaintext load failed: {str(e)}")
            return {}

    def _validate_config(self, config: Dict) -> Dict:
        """Comprehensive config validation"""
        if not isinstance(config, dict):
            raise ValueError("Config must be a dictionary")

        # Version migration
        if config.get("version") != CONFIG_VERSION:
            config = self._migrate_config(config)

        # Required fields check
        required = {
            "qb_client_id": str,
            "qb_client_secret": str,
            "redirect_uri": str
        }
        
        for field, field_type in required.items():
            if field not in config:
                raise ValueError(f"Missing required field: {field}")
            if not isinstance(config[field], field_type):
                raise ValueError(f"Invalid type for {field}")

        # Environment validation
        if "environment" in config:
            if config["environment"] not in ALLOWED_ENVIRONMENTS:
                raise ValueError(f"Invalid environment: {config['environment']}")

        return config

    def _migrate_config(self, config: Dict) -> Dict:
        """Handle config version migrations"""
        if "version" not in config:
            logger.warning("Migrating legacy config format")
            # Example migration:
            config = {
                **config,
                "version": CONFIG_VERSION,
                "environment": config.get("environment", "production")
            }
        return config

    def _create_default_config(self) -> Dict[str, Any]:
        """Generate safe default configuration"""
        return {
            "version": CONFIG_VERSION,
            "environment": "production",
            "debug": {
                "log_level": "INFO"
            }
        }

    def save_config(self, config: Dict[str, Any], *, 
                   create_backup: bool = True,
                   force_plaintext: bool = False) -> bool:
        """
        Atomic config save with backup and validation
        Args:
            create_backup: Maintain previous version as backup
            force_plaintext: Save unencrypted copy (warning: insecure)
        """
        try:
            validated = self._validate_config(config)
            
            # Always maintain backup
            if create_backup and self.config_path.exists():
                self._atomic_save(
                    self.backup_path,
                    self.config_path.read_bytes()
                )

            # Main encrypted save
            encrypted = self.cipher.encrypt(
                json.dumps(validated, indent=2).encode()
            )
            if not self._atomic_save(self.config_path, encrypted):
                return False

            # Optional plaintext save (not recommended for production)
            if force_plaintext:
                self._atomic_save(
                    self.plain_config_path,
                    json.dumps(validated, indent=2).encode()
                )

            return True

        except Exception as e:
            logger.error(f"Config save failed: {str(e)}")
            return False

    def _atomic_save(self, path: Path, data: bytes) -> bool:
        """Military-grade atomic save with checksum verification"""
        temp_path = path.with_suffix(f".tmp.{os.getpid()}")
        try:
            # Write with checksum
            temp_path.write_bytes(data)
            temp_path.chmod(0o600)
            
            # Verify write integrity
            if hashlib.sha256(data).hexdigest() != \
               hashlib.sha256(temp_path.read_bytes()).hexdigest():
                raise IOError("Checksum verification failed")

            # Atomic replace
            temp_path.replace(path)
            return True
        except Exception as e:
            logger.error(f"Atomic save failed for {path}: {str(e)}")
            return False
        finally:
            if temp_path.exists():
                temp_path.unlink()

    def rotate_key(self) -> bool:
        """Cryptographic key rotation procedure"""
        try:
            # Load existing config
            config = self.load_config()
            if not config:
                return False

            # Generate new key
            old_key = self.key
            self.key = Fernet.generate_key()

            # Re-encrypt everything
            if not self.save_config(config):
                self.key = old_key  # Rollback
                return False

            # Update key file
            key_path = Path("secret.key")
            temp_path = key_path.with_suffix(f".tmp.{os.getpid()}")
            temp_path.write_bytes(self.key)
            temp_path.chmod(0o600)
            temp_path.replace(key_path)

            logger.info("Successfully rotated encryption key")
            return True
        except Exception as e:
            logger.critical(f"Key rotation failed: {str(e)}")
            return False

# Singleton with thread safety
import threading
_config_manager_lock = threading.Lock()
_config_manager_instance = None

def get_config_manager() -> ConfigManager:
    """Thread-safe singleton access"""
    global _config_manager_instance
    with _config_manager_lock:
        if _config_manager_instance is None:
            _config_manager_instance = ConfigManager()
    return _config_manager_instance

# Public API
def load_config(**kwargs) -> Dict[str, Any]:
    return get_config_manager().load_config(**kwargs)

def save_config(config: Dict[str, Any], **kwargs) -> bool:
    return get_config_manager().save_config(config, **kwargs)

def rotate_key() -> bool:
    return get_config_manager().rotate_key()

def emergency_reset() -> bool:
    """Nuclear option for complete config reset"""
    manager = get_config_manager()
    paths = [
        manager.config_path,
        manager.plain_config_path,
        manager.backup_path
    ]
    try:
        for path in paths:
            if path.exists():
                path.unlink()
        logger.critical("PERFORMED EMERGENCY CONFIG RESET")
        return True
    except Exception as e:
        logger.error(f"Reset failed: {str(e)}")
        return False