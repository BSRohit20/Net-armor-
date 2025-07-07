@echo off
echo 🛡️  NET ARMOR - One-Click Global Deployment
echo =============================================
echo.

echo This will deploy your NET ARMOR app globally with minimal setup!
echo.

REM Check prerequisites
echo 🔍 Checking prerequisites...

REM Check Git
git --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ❌ Git not found. Installing via winget...
    winget install Git.Git
    if %errorlevel% neq 0 (
        echo ❌ Please install Git manually from: https://git-scm.com/download/win
        pause
        exit /b 1
    )
    echo ✅ Git installed. Please restart command prompt and run this script again.
    pause
    exit /b 0
)

REM Check Python
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ❌ Python not found. Please install Python 3.9+ from: https://python.org
    pause
    exit /b 1
)

echo ✅ Prerequisites OK
echo.

REM Setup Git repository
if not exist ".git" (
    echo 📁 Setting up Git repository...
    git init
    
    REM Fix Git ownership issues
    git config --global --add safe.directory "%CD%"
    
    git add .
    git commit -m "Initial commit - NET ARMOR Web Application"
    echo ✅ Git repository ready
) else (
    REM Fix Git ownership issues for existing repository
    git config --global --add safe.directory "%CD%"
)

echo 🚀 EASIEST DEPLOYMENT: Railway.app
echo ==================================
echo.
echo Railway.app requires NO CLI installation and deploys automatically!
echo.

echo Step 1: Creating GitHub repository...
echo 🌐 Opening GitHub...
start https://github.com/new

echo.
echo 📝 GitHub Setup Instructions:
echo 1. Repository name: net-armor-app
echo 2. Description: NET ARMOR Digital Security Toolkit  
echo 3. Set to Public
echo 4. Click "Create repository"
echo 5. Copy the HTTPS clone URL
echo.

set /p repo_url="Paste your GitHub repository URL here: "

if "%repo_url%"=="" (
    echo ❌ Repository URL required for deployment
    goto manual_instructions
)

echo 📤 Pushing code to GitHub...

REM Check if we have any commits
git log --oneline >nul 2>&1
if %errorlevel% neq 0 (
    echo 📝 No commits found. Creating initial commit...
    git add .
    git commit -m "Initial commit - NET ARMOR Web Application"
    if %errorlevel% neq 0 (
        echo ❌ Failed to create initial commit. Checking for files...
        dir /b
        echo Please ensure files are in the directory and try again.
        goto manual_instructions
    )
)

REM Remove existing remote if it exists
git remote remove origin >nul 2>&1

REM Add new remote
git remote add origin %repo_url%

REM Check current branch name
for /f "tokens=*" %%i in ('git branch --show-current 2^>nul') do set current_branch=%%i
if "%current_branch%"=="" (
    echo 📝 Setting up main branch...
    git checkout -b main
)

REM Push to GitHub
git push -u origin main

if %errorlevel% neq 0 (
    echo ❌ Failed to push to GitHub. Check the repository URL.
    goto manual_instructions
)

echo ✅ Code pushed to GitHub successfully!
echo.

echo Step 2: Deploying to Railway...
echo 🚀 Opening Railway.app...
start https://railway.app/new

echo.
echo 🎯 RAILWAY DEPLOYMENT INSTRUCTIONS:
echo ==========================================
echo.
echo 1. Click "Login" → Sign in with GitHub
echo 2. Click "Deploy from GitHub repo"  
echo 3. Select your "net-armor-app" repository
echo 4. Railway auto-detects Flask - click "Deploy"
echo 5. Wait for build to complete (2-3 minutes)
echo 6. Click on your deployment
echo 7. Go to "Variables" tab
echo 8. Add these environment variables:
echo    Name: SECRET_KEY
echo    Value: %RANDOM%%RANDOM%%RANDOM%%TIME:~-2%%DATE:~-2%
echo.
echo    Name: FLASK_ENV  
echo    Value: production
echo.
echo 9. Your app will be live at: https://[random].up.railway.app
echo.

echo 🎉 DEPLOYMENT COMPLETE!
echo.
echo 🌍 Your NET ARMOR toolkit is now globally accessible!
echo 📱 Share the Railway URL with users worldwide
echo 🔒 All security tools work from any device/browser
echo.
goto end

:manual_instructions
echo.
echo 📖 MANUAL DEPLOYMENT OPTION:
echo ============================
echo.
echo If automated setup failed, you can:
echo.
echo 1. Push code to GitHub manually:
echo    git remote add origin YOUR_REPO_URL
echo    git push -u origin main
echo.
echo 2. Deploy using Railway.app, Vercel, or Netlify
echo 3. Set environment variables:
echo    SECRET_KEY=%RANDOM%%RANDOM%%RANDOM%
echo    FLASK_ENV=production
echo.

:end
echo 📞 Need help? Check README.md or run deploy.bat for more options
echo.
pause
