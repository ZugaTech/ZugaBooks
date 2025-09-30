from config import ConfigManager

# Instantiate the ConfigManager
config = ConfigManager()

# Update the Realm ID (replace with your actual Realm ID)
config.set("realm_id", "9341454953961084")

# Confirm the update
print("Updated Realm ID:", config.get("realm_id"))