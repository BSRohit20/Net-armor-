@echo off
echo Installing NET ARMOR Web Application...
echo.

echo Step 1: Installing Python dependencies...
pip install -r requirements.txt
if %errorlevel% neq 0 (
    echo Error: Failed to install dependencies
    pause
    exit /b 1
)

echo.
echo Step 2: Starting the web application...
echo.
echo NET ARMOR Web App will be available at:
echo   Local:   http://localhost:5000
echo   Network: http://%COMPUTERNAME%:5000
echo.
echo Press Ctrl+C to stop the application
echo.

python app.py
