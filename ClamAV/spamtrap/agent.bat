@echo off
rem {SOURCEIP} {SENDER} {RECIPIENTS} {EMAILFILESPEC}
rem %1         %2       %3           %4
rem ExitCode:
rem	0 - pass,
rem	1 - tag,
rem	2 - reject,
rem	3 - error

set clamdscan_run="C:\Program Files\ClamAV\clamdscan.exe" --infected --no-summary --stdout --config-file="C:\Program Files\ClamAV\clamd_spam.conf"
rem set dccproc_run="C:\Program Files\ClamAV\spamtrap\dccproc.exe" -Q -H -m "C:\Program Files\ClamAV\spamtrap\dcc.map"
set dccproc_run="C:\Program Files\ClamAV\spamtrap\dccproc.exe" -H -m "C:\Program Files\ClamAV\spamtrap\dcc.map"
rem set dcc_log=nul
set dcc_log=C:\Program Files\ClamAV\logs\spamtrap_dcc.log
set trap_file=C:\Program Files\ClamAV\spamtrap\list_trap.txt
set rbl_file=C:\Program Files\ClamAV\spamtrap\list_rbl.txt
set stat_file=C:\Program Files\ClamAV\logs\spamtrap.stat

set source_ip=%1
set sender_addr=%2
set recipients=%3
set recipients=%recipients:"=%
set email_file=%4


call :dcc_check %source_ip% %email_file% dcc_resp
if ERRORLEVEL 1 set hit_dcc=true

%clamdscan_run% %email_file%
if ERRORLEVEL 2 exit /B 3
if not ERRORLEVEL 1 exit /B 0

if "%hit_dcc%"=="true" (
  echo %dcc_resp% >> "%dcc_log%"
  echo SPAM-hash detected and DCC confirm. & exit /B 2
)

call :rbl_check_any %source_ip% "%rbl_file%" rbl_name rbl_resp
if ERRORLEVEL 1 set hit_rbl=true

call :stat_update "%stat_file%" "%rbl_file%" %rbl_name%
if "%hit_rbl%"=="true" echo SPAM-hash detected and the %rbl_name% DNSBL hit: %rbl_resp%. & exit /B 2

echo SPAM-hash detected.
exit /B 1


rem ================
rem %1 - source IP
rem %2 - file with EMail-message
rem %3 - response from DCC
rem exitCode - 0/1
rem ================
:dcc_check

for /F "tokens=*" %%i in ('start "" /B /WAIT %dccproc_run% -a %1 -i %2 2^> nul ^| findstr /C:"=many"') do (
  set %3=%%i
  exit /B 1
)

exit /B 0


rem ================
rem %1 - original IP
rem %2 - name of variable for inversed IP
rem ================
:ip_reverse

for /F "tokens=1-4 delims=." %%i in ("%1") do set %2=%%l.%%k.%%j.%%i
exit /B 0


rem ================
rem %1 - dns-name for request in RBL-format
rem %2 - name of variable for response of RBL-server
rem %3 - valid responses ("127.0.0.2 127.0.1.1")
rem exitCode - 0/1
rem ================
:rbl_lookup

setlocal EnableDelayedExpansion

for /F "tokens=1,2" %%i in ('nslookup %1 2^> nul ^| findstr /E /L %3') do (
  if "%%j"=="" ( set rblresp=!rblresp! %%i ) else ( set rblresp=!rblresp! %%j )
)

if "!rblresp!"=="" endlocal & exit /B 0
endlocal & set %2=%rblresp% & exit /B 1


rem ================
rem %1 - IP for check
rem %2 - file with list of RBL's
rem %3 - short name RBL with present this IP
rem %4 - response from RBL
rem exitCode - 0/1
rem ================
:rbl_check_any

call :ip_reverse %1 rvip
for /F "usebackq eol=; tokens=1,2,*" %%i in (%2) do (
  call :rbl_lookup %rvip%.%%j resp %%k
  if ERRORLEVEL 1 set %3=%%i & goto :rbl_check_any_hit
)

exit /B 0

:rbl_check_any_hit
set %4=%resp%
exit /B 1


rem ================
rem %1 - file for Statistics
rem %2 - file with RBL-list
rem %3 - short name of RBL that need update
rem ================
:stat_update

setlocal EnableDelayedExpansion

set /A rblcnt=0
for /F "usebackq eol=; tokens=1" %%i in (%2) do (
  set /A stat=0
  for /F "eol=; tokens=2" %%j in ('findstr /B /L /C:"%%i" %1 2^> nul') do set /A stat=%%j
  if "%%i"=="%3" set /A stat=!stat!+1
  set /A rblcnt=!rblcnt!+1
  set line.!rblcnt!=%%i !stat!
)

set /A testcnt=0
for /F "eol=; tokens=2" %%i in ('findstr /B /L /C:"Tests:" %1 2^> nul') do set /A testcnt=%%i
set /A testcnt=!testcnt!+1

echo Tests: !testcnt!> %1
for /L %%i in (1,1,!rblcnt!) do echo !line.%%i!>> %1

endlocal
exit /B 0
