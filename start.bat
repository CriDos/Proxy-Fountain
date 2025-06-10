@echo off
setlocal

:: ==========================================================
::      Запускатор для Proxy-Fountain на Windows
:: ==========================================================

:: Устанавливаем заголовок окна консоли
title Proxy-Fountain Runner

:: Имя основного Python-скрипта
set SCRIPT_NAME=proxy_fountain.py

:: Имя папки виртуального окружения
set VENV_DIR=venv

:: --- Проверка наличия Python ---
echo Checking for Python...
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python not found in your system's PATH.
    echo Please install Python 3 and make sure it's added to PATH.
    pause
    exit /b 1
)
echo Python found.

:: --- Настройка виртуального окружения ---
echo Checking for virtual environment...
if not exist "%VENV_DIR%\Scripts\activate" (
    echo [INFO] Virtual environment not found. Creating one...
    python -m venv %VENV_DIR%
    if %errorlevel% neq 0 (
        echo [ERROR] Failed to create virtual environment.
        pause
        exit /b 1
    )
    echo Virtual environment created successfully.
) else (
    echo Virtual environment already exists.
)

:: --- Активация виртуального окружения и установка зависимостей ---
echo Activating virtual environment and installing/updating dependencies...
call "%VENV_DIR%\Scripts\activate.bat"
pip install -r requirements.txt
if %errorlevel% neq 0 (
    echo [ERROR] Failed to install dependencies from requirements.txt.
    pause
    exit /b 1
)

:: --- Основной цикл запуска ---
echo ==========================================================
echo Starting %SCRIPT_NAME%...
echo To stop the server, press Ctrl+C in this window.
echo ==========================================================

:start_loop
    :: Запускаем основной скрипт
    python %SCRIPT_NAME%
    
    :: Если скрипт завершился (например, из-за ошибки), errorlevel будет не равен 0
    if %errorlevel% neq 0 (
        echo.
        echo [WARNING] The script has stopped with an error (code: %errorlevel%).
        echo Waiting for 10 seconds before restarting...
        timeout /t 10
        goto start_loop
    )

:: Этот код выполнится, только если скрипт завершится без ошибок (например, по Ctrl+C)
echo [INFO] The script has finished its work.
pause
exit /b 0