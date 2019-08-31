@ECHO OFF
SETLOCAL

SET logsep=------------------------------------------
SET cmd=%*

ECHO %logsep%
ECHO Start time: %date% %time%
ECHO Running command: %cmd%
ECHO.

%cmd%

SET err=%ERRORLEVEL%

ECHO.

IF %err% equ 0 GOTO success
:error
ECHO Command exited with non-zero return code: %err%
GOTO exit

:success
ECHO Command succeeded^!

:exit
ECHO End time: %date% %time%
ECHO %logsep%
EXIT /B %err%
