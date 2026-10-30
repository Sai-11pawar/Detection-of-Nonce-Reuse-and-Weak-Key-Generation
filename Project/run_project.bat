@echo off
setlocal
cd /d "%~dp0"

where py >nul 2>nul
if %errorlevel%==0 (
    set "PYTHON=py"
) else (
    where python >nul 2>nul
    if %errorlevel%==0 (
        set "PYTHON=python"
    ) else (
        echo Python was not found. Install Python 3.10 or newer from https://www.python.org/downloads/
        echo During installation, enable "Add Python to PATH", then reopen this window.
        pause
        exit /b 1
    )
)

%PYTHON% -c "import sys; raise SystemExit(sys.version_info < (3,10))"
if errorlevel 1 (
    echo Python 3.10 or newer is required. Install a current Python version and try again.
    pause
    exit /b 1
)

if not exist ".venv\Scripts\python.exe" (
    echo Creating the project's virtual environment...
    %PYTHON% -m venv .venv
    if errorlevel 1 goto :error
)

call ".venv\Scripts\activate.bat"
echo Installing or checking project packages...
python -m pip install -r requirements.txt
if errorlevel 1 goto :error
echo Starting the dashboard. Keep this window open while using the app.
python -m streamlit run app.py
if errorlevel 1 goto :error
exit /b 0

:error
echo.
echo The project could not start. Check that Python 3.10+ is installed and that this PC can reach
echo the Python package index for the first-time package installation.
echo You can also open a terminal in this folder and run: .venv\Scripts\python -m pytest
pause
exit /b 1
