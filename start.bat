@echo off
chcp 65001 >nul
cd /d "%~dp0"
echo.
echo   Dang khoi dong ban demo CMS Quan tri khoa...
echo.
start "" http://localhost:4300
node server.js
