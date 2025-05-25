
ZUGABOOKS REPORTING TOOL – INSTALLATION & USAGE GUIDE
======================================================

Welcome! This tool helps export QuickBooks reports to Google Sheets using a simple Streamlit interface.

📁 FOLDER STRUCTURE
-------------------
Place all the following files in a single folder:
- app.py                  → The main Streamlit app
- config.json             → Your QuickBooks + Google Sheets config file
- sa.json                 → Google Service Account JSON key
- requirements.txt        → (Optional) List of Python dependencies
- run_zugabooks.bat       → Windows launcher script (auto-setup)

🧰 ONE-TIME SETUP (Handled Automatically)
----------------------------------------
When you first double-click `run_zugabooks.bat`, it will:
1. Check if Python is installed (prompts you if not)
2. Create a virtual environment `.venv`
3. Install required packages (`streamlit`, `quickbooks-python`, `gspread`, etc.)
4. Validate presence of `config.json` and `sa.json`
5. Launch the app in your default browser

🚀 HOW TO RUN
-------------
1. Double-click `run_zugabooks.bat`
2. Wait for setup to finish
3. Your browser will open to: http://localhost:8501/
4. Follow the steps in the app sidebar:
   - Authorize QuickBooks
   - Select report type and date range
   - Upload category CSV (optional)
   - Click "Fetch & Export"

📝 config.json FORMAT
---------------------
Create a `config.json` with the following:
{
  "qb_client_id": "YOUR_CLIENT_ID",
  "qb_client_secret": "YOUR_CLIENT_SECRET",
  "redirect_uri": "http://localhost:8501/callback",
  "realm_id": "YOUR_REALM_ID",
  "sheet_id": "YOUR_GOOGLE_SHEET_ID"
}

📌 NOTES
--------
- If changing company or Sheets, just update `config.json`
- Do NOT share `sa.json` or `config.json` publicly
- Only the first QuickBooks authorization requires a browser code copy

💡 NEED HELP?
-------------
Contact the original developer for setup support or enhancements.

