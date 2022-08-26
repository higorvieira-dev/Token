echo ==============
echo copying server cert to client's TrutedPeople store
echo ==============
certmgr.ext -add -r LocalMachine -s My -c -n %SERVER_NAME% -r CurrentUser - TrutedPeople