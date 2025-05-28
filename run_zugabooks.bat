@echo off
SETLOCAL ENABLEDELAYEDEXPANSION

REM Go to current script directory
PUSHD "%~dp0"

REM Check Python
python --version >nul 2>&1
IF ERRORLEVEL 1 (
    echo Python not found in PATH. Please install Python 3.9+ and try again.
    PAUSE
    EXIT /B 1
)

REM Setup virtual environment
IF EXIST "venv\Scripts\activate.bat" (
    echo Activating existing virtual environment...
) ELSE (
    echo Creating virtual environment...
    python -m venv venv
)

CALL "venv\Scripts\activate.bat"

REM Upgrade pip & install requirements
echo Installing/updating dependencies...
venv\Scripts\python.exe -m pip install --upgrade pip

IF EXIST "requirements.txt" (
    venv\Scripts\python.exe -m pip install -r requirements.txt
) ELSE (
    venv\Scripts\python.exe -m pip install streamlit pandas gspread oauth2client python-quickbooks
)

REM Check essential files
IF NOT EXIST "config.json" (
    echo ERROR: config.json not found in %CD%.
    PAUSE
    EXIT /B 1
)
IF NOT EXIST "sa.json" (
    echo ERROR: sa.json not found in %CD%.
    PAUSE
    EXIT /B 1
)

REM Run Streamlit app and keep window open
echo Launching ZugaBooks app...
start "" http://localhost:8501
cmd /k "streamlit run app.py"

ENDLOCAL
