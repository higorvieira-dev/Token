echo ==============
echo Server cert Setup starting
echo %SERVER_NAME%
echo ==============
echo making server cert
echo ==============
make.exe -sr LocalMachine -ss MY -a sha1 -n CN=%SERVER_NAME% -sky exchange -pe