@echo off

REM CA Service
start cmd /k "python -m securemail.main_ca serve"

timeout /t 2 >nul

REM Key Distribution Server
start cmd /k "python -m securemail.main_kds"

timeout /t 2 >nul

REM Ticket Service
start cmd /k "python -m securemail.main_ticket"

timeout /t 2 >nul

REM Bootstrap (run once)
python -m securemail.run_demo bootstrap

timeout /t 2 >nul

REM Mail Server
start cmd /k "python -m securemail.main_mail_server"

echo All services started.
pause