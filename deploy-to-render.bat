@echo off
echo.
echo =============================================
echo       NET ARMOR - Render Deployment
echo =============================================
echo.

REM Check if git is available
git --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Git is not installed or not in PATH
    echo Please install Git first: https://git-scm.com/download/win
    pause
    exit /b 1
)

echo [INFO] Preparing files for Render deployment...

REM Ensure all files are committed
echo [INFO] Adding all files to git...
git add .

echo [INFO] Committing changes...
git commit -m "Prepare for Render deployment - %date% %time%"

echo [INFO] Pushing to GitHub...
git push origin main

if errorlevel 1 (
    echo [WARNING] Git push failed - you may need to set up remote first
    echo Run: git remote add origin https://github.com/yourusername/your-repo.git
)

echo.
echo =============================================
echo        Deployment Instructions
echo =============================================
echo.
echo 1. Go to https://render.com and sign up/login
echo 2. Click "New +" then "Web Service"
echo 3. Connect your GitHub repository
echo 4. Use these settings:
echo    - Name: net-armor-security-toolkit
echo    - Runtime: Python 3
echo    - Build Command: pip install -r requirements.txt
echo    - Start Command: gunicorn app:app
echo    - Branch: main
echo.
echo 5. Add environment variables (optional):
echo    - FLASK_ENV=production
echo    - SECRET_KEY=your-secret-key-here
echo.
echo 6. Click "Create Web Service" and wait 2-3 minutes
echo.
echo Your app will be live at:
echo https://your-app-name.onrender.com
echo.
echo For detailed instructions, see: RENDER_DEPLOYMENT_GUIDE.md
echo.

pause
