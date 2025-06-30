@echo off
echo 🛡️  NET ARMOR - Quick Global Deployment
echo =========================================
echo.

echo This script will help you deploy NET ARMOR globally in the easiest way possible!
echo.

REM Check if git is installed
git --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ❌ Git is required but not found!
    echo.
    echo 📥 INSTALLING GIT:
    echo 1. Download from: https://git-scm.com/download/win
    echo 2. Install with default settings
    echo 3. Restart command prompt
    echo 4. Run this script again
    echo.
    echo 💡 Alternative: Use winget install Git.Git
    pause
    exit /b 1
)

REM Initialize git repository if needed
if not exist ".git" (
    echo 📁 Setting up Git repository...
    git init
    git add .
    git commit -m "Initial commit - NET ARMOR Web Application"
    echo ✅ Git repository created
    echo.
)

echo Choose the EASIEST deployment method:
echo.
echo 1. 🚀 Railway.app (Recommended - No CLI needed)
echo 2. 🌊 GitHub + Vercel (Free, fast)
echo 3. 🔧 GitHub + Netlify (Static + serverless)
echo 4. 📱 GitHub repository only (manual deployment later)
echo.

set /p choice="Enter your choice (1-4): "

if "%choice%"=="1" goto railway
if "%choice%"=="2" goto vercel
if "%choice%"=="3" goto netlify
if "%choice%"=="4" goto github_only
goto invalid

:railway
echo.
echo 🚀 RAILWAY.APP DEPLOYMENT (EASIEST!)
echo ====================================
echo.
echo Railway.app is the easiest way to deploy your app globally!
echo.
echo 📋 AUTOMATIC SETUP STEPS:
echo.
echo Step 1: Create GitHub repository (optional but recommended)
set /p create_github="Do you want to create a GitHub repository? (y/n): "
if /i "%create_github%"=="y" (
    echo.
    echo 🔗 Opening GitHub...
    start https://github.com/new
    echo.
    echo 📝 Instructions:
    echo 1. Repository name: net-armor
    echo 2. Description: NET ARMOR - Digital Security Toolkit
    echo 3. Make it Public
    echo 4. Click "Create repository"
    echo 5. Copy the repository URL
    echo.
    pause
    
    set /p repo_url="Enter your GitHub repository URL: "
    if not "!repo_url!"=="" (
        git remote add origin !repo_url!
        git branch -M main
        git push -u origin main
        echo ✅ Code pushed to GitHub
    )
)

echo.
echo Step 2: Deploy to Railway
echo 🌐 Opening Railway.app...
start https://railway.app/
echo.
echo 📋 RAILWAY DEPLOYMENT INSTRUCTIONS:
echo.
echo 1. Click "Login" and sign up with GitHub
echo 2. Click "New Project"
echo 3. Choose "Deploy from GitHub repo"
echo 4. Select your NET ARMOR repository
echo 5. Railway will auto-detect Flask and start building
echo 6. Once deployed, go to Settings → Environment
echo 7. Add these variables:
echo    - SECRET_KEY: %RANDOM%%RANDOM%%RANDOM%
echo    - FLASK_ENV: production
echo 8. Your app will be live at: https://your-app.up.railway.app
echo.
echo 🎉 That's it! Your app will be globally accessible!
goto end

:vercel
echo.
echo 🌊 GITHUB + VERCEL DEPLOYMENT
echo =============================
echo.
echo Step 1: Push to GitHub
start https://github.com/new
echo Create a new repository and copy the URL.
echo.
set /p repo_url="Enter your GitHub repository URL: "
if not "%repo_url%"=="" (
    git remote add origin %repo_url%
    git branch -M main
    git push -u origin main
)

echo.
echo Step 2: Deploy with Vercel
start https://vercel.com/new
echo.
echo 📋 VERCEL INSTRUCTIONS:
echo 1. Sign up with GitHub
echo 2. Import your NET ARMOR repository
echo 3. Vercel will auto-configure for Flask
echo 4. Add environment variables:
echo    - SECRET_KEY: (generate random)
echo    - FLASK_ENV: production
echo 5. Deploy!
goto end

:netlify
echo.
echo 🔧 GITHUB + NETLIFY DEPLOYMENT
echo ==============================
echo.
echo Step 1: Push to GitHub
start https://github.com/new
echo Create repository and copy URL.
echo.
set /p repo_url="Enter your GitHub repository URL: "
if not "%repo_url%"=="" (
    git remote add origin %repo_url%
    git branch -M main
    git push -u origin main
)

echo.
echo Step 2: Deploy with Netlify
start https://app.netlify.com/start
echo.
echo 📋 NETLIFY INSTRUCTIONS:
echo 1. Connect with GitHub
echo 2. Choose your NET ARMOR repository
echo 3. Build settings will be auto-detected
echo 4. Add environment variables in Site settings
echo 5. Deploy!
goto end

:github_only
echo.
echo 📱 GITHUB REPOSITORY SETUP
echo ==========================
echo.
start https://github.com/new
echo.
echo 📋 GITHUB SETUP:
echo 1. Repository name: net-armor
echo 2. Description: NET ARMOR - Digital Security Toolkit
echo 3. Make it Public
echo 4. Create repository
echo 5. Copy the repository URL
echo.
set /p repo_url="Enter your GitHub repository URL: "
if not "%repo_url%"=="" (
    git remote add origin %repo_url%
    git branch -M main
    git push -u origin main
    echo ✅ Code pushed to GitHub!
    echo.
    echo 🚀 Now you can deploy from GitHub to:
    echo - Railway.app
    echo - Vercel
    echo - Netlify
    echo - Heroku
    echo - DigitalOcean
)
goto end

:invalid
echo Invalid choice. Please try again.
goto end

:end
echo.
echo 🎉 DEPLOYMENT COMPLETE!
echo.
echo 🌍 Your NET ARMOR app will be accessible globally!
echo 🔒 Users can access all security tools from anywhere
echo 📱 Works on desktop, mobile, and tablets
echo.
echo 📞 Need help? Check README.md for detailed instructions!
echo.
pause
