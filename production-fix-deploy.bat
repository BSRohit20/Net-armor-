@echo off
echo ==============================================
echo   NET ARMOR - Production Deployment Fix
echo ==============================================
echo.

echo Fixing deployment issues and pushing to production...
echo.

echo [1/5] Adding all changes to git...
git add .

echo [2/5] Committing fixes...
git commit -m "Fix: Production deployment issues - in-memory storage, error handling, environment configs"

echo [3/5] Pushing to GitHub...
git push origin main

echo [4/5] Deploying to Railway (if connected)...
railway up

echo [5/5] Deployment complete!
echo.
echo Your app should now be accessible at:
echo - Railway: Check your Railway dashboard for the URL
echo - Local: http://localhost:5000
echo.
echo If you encounter any issues:
echo 1. Check the Railway logs: railway logs
echo 2. Verify environment variables are set
echo 3. Ensure your domain is added to Google OAuth (if using)
echo.
pause
