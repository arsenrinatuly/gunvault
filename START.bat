@echo off
cd /d "%~dp0"
echo.
echo  ============================================
echo   GunVault - FFL Management Software
echo  ============================================
echo.

echo  [1] Checking Node.js...
node --version
if %errorlevel% neq 0 (
    echo  ERROR: Node.js not found!
    pause
    exit /b 1
)

echo  [2] Installing packages...
call npm install
if %errorlevel% neq 0 (
    echo  ERROR: npm install failed!
    pause
    exit /b 1
)

echo  [3] Packages OK.
echo.
echo  Server:  http://localhost:3000
echo  Admin:   http://localhost:3000/admin
echo.
echo  Press Ctrl+C to stop the server.
echo.

node server.js

echo.
echo  Server stopped.
pause
