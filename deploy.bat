@echo off
setlocal enabledelayedexpansion
echo 🛡️  NET ARMOR - Global Deployment Options
echo ==========================================
echo.

echo Choose your deployment method:
echo 1. 🚀 Heroku (Free tier available)
echo 2. 🐳 Docker Container  
echo 3. ☁️  Railway.app (Simple deployment)
echo 4. 🌊 DigitalOcean App Platform
echo 5. 📦 Manual deployment guide
echo.

set /p choice="Enter your choice (1-5): "

if "%choice%"=="1" goto heroku
if "%choice%"=="2" goto docker
if "%choice%"=="3" goto railway
if "%choice%"=="4" goto digitalocean
if "%choice%"=="5" goto manual
goto invalid

:heroku
echo.
echo 🚀 HEROKU DEPLOYMENT
echo ====================
echo.

REM Check if Heroku CLI is installed
heroku --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ❌ Heroku CLI not found!
    echo.
    echo 📥 INSTALLING HEROKU CLI...
    echo.
    echo Please choose an installation method:
    echo 1. Download installer (Recommended)
    echo 2. Install via winget (if available)
    echo 3. Manual installation guide
    echo.
    set /p install_choice="Enter choice (1-3): "
    
    if "!install_choice!"=="1" (
        echo Opening Heroku CLI download page...
        start https://devcenter.heroku.com/articles/heroku-cli#download-and-install
        echo.
        echo 📋 Steps:
        echo 1. Download and install Heroku CLI from the opened page
        echo 2. Restart this script after installation
        echo 3. Create Heroku account at: https://signup.heroku.com/
        goto end
    )
    
    if "!install_choice!"=="2" (
        echo Attempting winget installation...
        winget install Heroku.HerokuCLI
        if !errorlevel! neq 0 (
            echo ❌ winget installation failed. Please use option 1.
            goto end
        )
        echo ✅ Heroku CLI installed via winget
        echo Please restart this script to continue.
        goto end
    )
    
    if "!install_choice!"=="3" (
        echo.
        echo 📖 MANUAL INSTALLATION:
        echo 1. Visit: https://devcenter.heroku.com/articles/heroku-cli
        echo 2. Download the Windows installer
        echo 3. Run the installer as administrator
        echo 4. Restart command prompt
        echo 5. Run this script again
        echo.
        echo 💡 Alternative: Use winget install Heroku.HerokuCLI
        goto end
    )
    
    echo Invalid choice. Please run the script again.
    goto end
)

REM Check if git is installed
git --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ❌ Git not found!
    echo.
    echo Please install Git first:
    echo 1. Visit: https://git-scm.com/download/win
    echo 2. Download and install Git for Windows
    echo 3. Restart command prompt
    echo 4. Run this script again
    goto end
)

REM Check if this is a git repository
if not exist ".git" (
    echo 📁 Initializing Git repository...
    git init
    if %errorlevel% neq 0 (
        echo ❌ Failed to initialize Git repository
        goto end
    )
    
    git add .
    git commit -m "Initial commit - NET ARMOR Web Application"
    if %errorlevel% neq 0 (
        echo ❌ Failed to create initial commit
        goto end
    )
    echo ✅ Git repository initialized
)

echo ✅ Prerequisites check passed!
echo.
echo 🔐 HEROKU SETUP STEPS:
echo.

REM Check if user is logged in to Heroku
heroku auth:whoami >nul 2>&1
if %errorlevel% neq 0 (
    echo Step 1: Login to Heroku
    echo Running: heroku login
    echo.
    heroku login
    if %errorlevel% neq 0 (
        echo ❌ Heroku login failed
        goto end
    )
)

echo Step 2: Create Heroku app
set /p app_name="Enter your app name (e.g., my-netarmor): "
if "%app_name%"=="" set app_name=netarmor-app

echo Creating Heroku app: %app_name%
heroku create %app_name%
if %errorlevel% neq 0 (
    echo ❌ Failed to create app (name might be taken)
    echo Try a different name or add random numbers
    goto end
)

echo Step 3: Set environment variables
python -c "import secrets; print('SECRET_KEY=' + secrets.token_hex(32))" > temp_secret.txt
set /p secret_line=<temp_secret.txt
heroku config:set %secret_line%
heroku config:set FLASK_ENV=production
del temp_secret.txt

echo Step 4: Deploy to Heroku
git push heroku main
if %errorlevel% neq 0 (
    echo ❌ Deployment failed
    echo Check the error messages above
    goto end
)

echo.
echo 🎉 SUCCESS! Your NET ARMOR app is now live!
echo.
echo 🌐 Your app URL: https://%app_name%.herokuapp.com
echo 📊 Heroku dashboard: https://dashboard.heroku.com/apps/%app_name%
echo.
echo 📋 Next steps:
echo - Visit your app URL to test it
echo - Share the URL with users worldwide
echo - Monitor logs: heroku logs --tail
echo.
goto end

:docker
echo.
echo 🐳 DOCKER DEPLOYMENT
echo ===================
echo.
echo Prerequisites:
echo - Install Docker: https://www.docker.com/get-started
echo.
echo Commands to run:
echo 1. docker build -t netarmor .
echo 2. docker run -p 5000:5000 -e SECRET_KEY=your-secret-key netarmor
echo.
echo Or use Docker Compose:
echo 1. Update SECRET_KEY in docker-compose.yml
echo 2. docker-compose up -d
echo.
echo Access at: http://localhost:5000
goto end

:railway
echo.
echo ☁️  RAILWAY.APP DEPLOYMENT
echo =========================
echo.
echo Steps:
echo 1. Visit: https://railway.app/
echo 2. Sign up with GitHub
echo 3. Click 'New Project' → 'Deploy from GitHub repo'
echo 4. Select your NET ARMOR repository
echo 5. Railway will auto-detect Flask and deploy
echo 6. Set environment variables:
echo    - SECRET_KEY: (generate random key)
echo    - FLASK_ENV: production
echo.
echo Your app will get a railway.app subdomain automatically!
goto end

:digitalocean
echo.
echo 🌊 DIGITALOCEAN APP PLATFORM
echo ============================
echo.
echo Steps:
echo 1. Visit: https://cloud.digitalocean.com/apps
echo 2. Click 'Create App'
echo 3. Connect your GitHub repository
echo 4. DigitalOcean will detect Python/Flask
echo 5. Configure environment variables:
echo    - SECRET_KEY: (generate random key)
echo    - FLASK_ENV: production
echo 6. Deploy!
echo.
echo Cost: ~$5/month for basic app
goto end

:manual
echo.
echo 📦 MANUAL VPS DEPLOYMENT
echo =======================
echo.
echo For Windows Server or VPS:
echo.
echo 1. Install Python 3.9+ and Git
echo 2. Clone repository: git clone your-repo-url
echo 3. Install dependencies: pip install -r requirements.txt
echo 4. Set environment variables:
echo    set SECRET_KEY=your-random-secret-key
echo    set FLASK_ENV=production
echo 5. Run: gunicorn --bind 0.0.0.0:5000 app:app
echo.
echo For Linux VPS, run deploy.sh for detailed instructions
goto end

:invalid
echo Invalid choice. Please run the script again.
goto end

:end
echo.
echo 🔒 SECURITY REMINDERS:
echo - Always change the SECRET_KEY in production
echo - Use HTTPS in production (Let's Encrypt is free)
echo - Consider adding rate limiting for production use
echo - Regular backups of user data
echo.
echo 📞 Need help? Check the README.md file for detailed instructions!
echo.
pause
