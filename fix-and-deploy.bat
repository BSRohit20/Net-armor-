@echo off
setlocal enabledelayedexpansion
echo 🔧 NET ARMOR - Quick Fix for Git Ownership Issue
echo =================================================
echo.

echo Fixing Git ownership issue...
git config --global --add safe.directory "D:/Projects/NET ARMOR"

echo ✅ Git ownership fixed!
echo.

echo Now pushing to GitHub...

REM Check if we have any commits
git log --oneline >nul 2>&1
if %errorlevel% neq 0 (
    echo 📝 No commits found. Creating initial commit...
    git add .
    git commit -m "Initial commit - NET ARMOR Web Application"
)

REM Remove existing remote if it exists
git remote remove origin >nul 2>&1

REM Add the repository remote
git remote add origin https://github.com/BSRohit20/Net-armor-.git

REM Ensure we're on main branch
git checkout -b main >nul 2>&1
git branch -M main >nul 2>&1

REM Push to GitHub
git push -u origin main

if %errorlevel% neq 0 (
    echo ❌ Push failed. Let's try removing and re-adding the remote...
    git remote remove origin
    git remote add origin https://github.com/BSRohit20/Net-armor-
    git push -u origin main
)

if %errorlevel% neq 0 (
    echo ❌ Still having issues. Let's check the repository URL format...
    echo.
    echo Please verify your GitHub repository URL ends with .git
    echo Example: https://github.com/BSRohit20/Net-armor.git
    echo.
    set /p correct_url="Enter the correct repository URL (with .git): "
    if not "!correct_url!"=="" (
        git remote remove origin
        git remote add origin !correct_url!
        git push -u origin main
    )
) else (
    echo ✅ Code successfully pushed to GitHub!
    echo.
    echo 🚀 Now opening Railway.app for deployment...
    start https://railway.app/new
    echo.
    echo 🎯 RAILWAY DEPLOYMENT STEPS:
    echo 1. Sign in with GitHub
    echo 2. Click "Deploy from GitHub repo"
    echo 3. Select "Net-armor-" repository
    echo 4. Wait for auto-deployment
    echo 5. Add environment variables:
    echo    SECRET_KEY: 12560174734336
    echo    FLASK_ENV: production
    echo.
    echo 🎉 Your app will be live shortly!
)

echo.
pause
