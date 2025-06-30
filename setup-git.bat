@echo off
echo 🛡️  NET ARMOR - Git Repository Setup
echo =====================================
echo.

echo Initializing Git repository for deployment...
echo.

REM Check if git is installed
git --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ❌ Git is not installed or not in PATH
    echo Please install Git from: https://git-scm.com/download/win
    pause
    exit /b 1
)

REM Initialize git repository
echo 📁 Initializing Git repository...
git init

REM Add all files
echo 📂 Adding files to Git...
git add .

REM Create initial commit
echo 💾 Creating initial commit...
git commit -m "Initial commit - NET ARMOR Web Application"

echo.
echo ✅ Git repository initialized successfully!
echo.
echo Next steps for deployment:
echo.
echo 🚀 HEROKU DEPLOYMENT:
echo 1. heroku login
echo 2. heroku create your-netarmor-app
echo 3. heroku config:set SECRET_KEY=your-random-secret-key
echo 4. git push heroku main
echo.
echo ☁️  GITHUB + RAILWAY/VERCEL:
echo 1. Create repository on GitHub
echo 2. git remote add origin https://github.com/yourusername/net-armor.git
echo 3. git push -u origin main
echo 4. Connect repository to Railway/Vercel
echo.
echo 📖 For detailed instructions, run: deploy.bat
echo.
pause
