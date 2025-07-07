@echo off
echo.
echo ====================================
echo   NET ARMOR - Quick Deploy Script
echo ====================================
echo.

echo Step 1: Adding changes to git...
git add -A
if %errorlevel% neq 0 (
    echo Error: Failed to add files to git
    pause
    exit /b 1
)

echo Step 2: Committing changes...
git commit -m "Add user authentication system with login/register functionality"
if %errorlevel% neq 0 (
    echo Error: Failed to commit changes
    pause
    exit /b 1
)

echo Step 3: Pushing to GitHub...
git push origin main
if %errorlevel% neq 0 (
    echo Error: Failed to push to GitHub
    pause
    exit /b 1
)

echo.
echo ====================================
echo   Deployment Complete!
echo ====================================
echo.
echo Your NET ARMOR application has been updated with:
echo - User Registration System
echo - User Login System  
echo - User Dashboard
echo - Session Management
echo - Protected Routes
echo - Hash Analyzer
echo - Data Breach Checker
echo - URL Security Scanner
echo.
echo Live URL: https://web-production-07c5d.up.railway.app/
echo.
echo Demo Login Credentials:
echo Username: demo
echo Password: demo123
echo.
pause
