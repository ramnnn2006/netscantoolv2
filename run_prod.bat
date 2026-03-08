@echo off
echo Starting NetScan v2 in production mode (Waitress)...
echo Access the site at: http://localhost:5000
echo.
waitress-serve --host=0.0.0.0 --port=5000 app:app
pause
