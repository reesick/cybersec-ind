@echo off
echo Starting CyberForesight Dashboard...

start "API" cmd /k "uvicorn api.main:app --reload --port 8000"

cd frontend
start "Frontend" cmd /k "npm run dev"
cd ..

echo.
echo API:      http://localhost:8000
echo Frontend: http://localhost:5173
echo API Docs: http://localhost:8000/docs
