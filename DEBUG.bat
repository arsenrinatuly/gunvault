@echo off
cd /d "%~dp0"
echo Folder: %cd%
echo.
echo --- Checking packages ---
npm install
echo.
echo --- Testing node:sqlite ---
node -e "const {DatabaseSync}=require('node:sqlite');console.log('sqlite OK');"
echo Exit: %errorlevel%
echo.
echo --- Running server ---
node server.js
echo.
echo Exit: %errorlevel%
pause
