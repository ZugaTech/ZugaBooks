from config import load_config, save_config

# Test save
test_data = {"test": "value"}
save_config(test_data)
print("Saved config:", test_data)

# Test load
loaded = load_config()
print("Loaded config:", loaded)
assert loaded == test_data, "Config mismatch!"
print("✅ Config system working!")