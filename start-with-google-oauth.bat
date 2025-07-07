@echo off
echo Setting up Google OAuth Demo Environment Variables...
echo.
echo IMPORTANT: Replace these with your actual Google OAuth credentials!
echo Get them from: https://console.cloud.google.com/
echo.

REM Demo values - REPLACE WITH REAL CREDENTIALS!
set GOOGLE_CLIENT_ID=your-google-client-id-here.googleusercontent.com
set GOOGLE_CLIENT_SECRET=your-google-client-secret-here

echo Environment variables set for this session.
echo.
echo Next steps:
echo 1. Get real credentials from Google Cloud Console
echo 2. Replace the values above with your actual credentials
echo 3. Run this script before starting the app
echo.
echo Starting NET ARMOR with Google OAuth support...
python app.py
