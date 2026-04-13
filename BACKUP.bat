@echo off
cd /d "%~dp0"
echo.
echo  GunVault Database Backup
echo  ========================
echo.
node backup.js
echo.
pause
