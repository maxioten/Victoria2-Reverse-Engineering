@echo off
setlocal

REM ============================================================
REM GOLDEN AGE - VICTORIA 2 UNOFFICIAL PATCH 3.05
REM Compatible con Windows y Linux (Wine / PortProton)
REM ============================================================

REM Carpeta raiz de Victoria 2
set "ROOT=%~dp0"

REM Carpeta destino
set "DESTINO=%ROOT%mod\Victoria 2 unofficial patch 3.05"

REM ============================================================
REM CREAR CARPETA SI NO EXISTE
REM ============================================================

if not exist "%DESTINO%" (
    mkdir "%DESTINO%"
)

REM ============================================================
REM COPIAR EJECUTABLES
REM ============================================================

echo.
echo [Golden Age] Copiando v2game.exe...
copy /Y "%ROOT%v2game.exe" "%DESTINO%\v2game.exe"

echo [Golden Age] Copiando victoria2.exe...
copy /Y "%ROOT%victoria2.exe" "%DESTINO%\victoria2.exe"

REM ============================================================
REM EJECUTAR INICIAR_PATCH.BAT
REM ============================================================

echo.
echo [Golden Age] Iniciando Victoria 2 Unofficial Patch 3.05...

cd /d "%DESTINO%"

call iniciar_patch.bat

exit /b
