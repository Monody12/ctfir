@echo off
rem Unsafe persistent installation retired; runner restores exact originals in finally.
python "%~dp0run_windows.py" %*
exit /b %ERRORLEVEL%
