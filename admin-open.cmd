@echo off
rem Open the admin UI in the default browser using the link saved by admin.cmd.
setlocal
pushd "%~dp0"
if not exist "state\admin-url.txt" goto missing
set /p URL=<state\admin-url.txt
start "" "%URL%"
popd
exit /b 0
:missing
echo Ссылки ещё нет. Запустите admin.cmd — он откроет браузер и сохранит ссылку.
exit /b 2
