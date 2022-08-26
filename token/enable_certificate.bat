echo ==============
echo setting privileges on server certificates
echo ==============
for /F "delims=" %%i ('"%ProgramFiles%\ServiceModelSampleTools\FindPrivateKey.exe" My LocalMachine -n CN^=%SERVER_NAME% -a') do set PRIVATE_KEY_FILE=%%i
set WP_ACCOUNT=NT AUTHORITY\NETWORK SERIVCE 
(ver | findstr /C:"5.1") && set WP_ACCOUNT=%COMPUTERNAME%ASPNET
echo Y|cacls.exe "%PRIVATE_KEY_FILE%" /E /G "%WP_ACCOUNT%":R 
iisreset
