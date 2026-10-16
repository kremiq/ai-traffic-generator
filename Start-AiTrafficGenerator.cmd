@echo off
rem Starts the AI Traffic Generator (window). Extra arguments are passed on, e.g. -NoGui -Apps chatgpt
powershell.exe -NoProfile -ExecutionPolicy Bypass -STA -File "%~dp0AiTrafficGenerator.ps1" %*
