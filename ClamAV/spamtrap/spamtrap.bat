set log_file=C:\Program Files\ClamAV\logs\spamtrap.log
set work_dir=C:\Program Files\ClamAV\spamtrap\temp
set base_dir=C:\Program Files\ClamAV\spamtrap\base
set sig_basename=spamtrap
set sig_ext=hdb
set sig_file=%base_dir%\%sig_basename%.%sig_ext%
set sig_age=14
set sigtool_exe=C:\Program Files\ClamAV\sigtool.exe
set clamscan_exe=C:\Program Files\ClamAV\clamscan.exe
set clamav_db=C:\Program Files\ClamAV\db_spam
set /A min_file_size=128


if "%1"=="rotate" (
  echo Started: %date%-%time% >"%log_file%"

  echo. >>"%log_file%"
  call :rotate "%base_dir%" "%sig_basename%" %sig_ext% %sig_age% 2>>"%log_file%"

  rem Copying all bases of signatures to ClamAV
  echo. >>"%log_file%"
  echo Copying signatures to ClamAV... >>"%log_file%"
  xcopy /R/Y "%base_dir%\%sig_basename%*.*" "%clamav_db%" >>"%log_file%" 2>>&1

  echo. >>"%log_file%"
  echo Finished: %date%-%time% >>"%log_file%"
  goto :EOF
)


echo Started: %date%-%time% >"%log_file%"

rem Get "incoming" e-mail's of "spamtrap" mailbox
echo. >>"%log_file%"
echo Get spamtrap-mailbox messages... >>"%log_file%"
mpop.exe -Q -C mpop.conf >>"%log_file%"

rem Remove already hashed EML-files
echo. >>"%log_file%"
echo Remove already hashed EML-files... >>"%log_file%"
if exist "%sig_file%" (
  "%clamscan_exe%" --database="%sig_file%" --leave-temps=no --recursive=no --remove=yes --infected --no-summary --scan-mail=yes --phishing-sigs=no --phishing-scan-urls=no --scan-pe=no --scan-elf=no --scan-ole2=no --scan-pdf=no --scan-swf=no --scan-html=no --scan-xmldocs=no --scan-hwp3=no --scan-archive=no --detect-broken=no "%work_dir%" >>"%log_file%" 2>>&1
)

rem Unpack EML to content files
echo. >>"%log_file%"
echo Unpack content of EML-files... >>"%log_file%"
mkdir "%work_dir%\eml_content" 2>>"%log_file%"
"%clamscan_exe%" --database="void.hdb" --leave-temps=yes --recursive=no --remove=no --quiet --scan-mail=yes --phishing-sigs=no --phishing-scan-urls=no --scan-pe=no --scan-elf=no --scan-ole2=no --scan-pdf=no --scan-swf=no --scan-html=no --scan-xmldocs=no --scan-hwp3=no --scan-archive=no --detect-broken=no --tempdir="%work_dir%\eml_content" "%work_dir%" >>"%log_file%" 2>>&1

rem Delete normalised text-files
echo. >>"%log_file%"
echo Delete normalised text-files... >>"%log_file%"
del /F/Q "%work_dir%\eml_content\*.*" 2>>"%log_file%"
rem del /F/S/Q "%work_dir%\eml_content\*.html" 2>>"%log_file%"

rem Calc sigs for content
echo. >>"%log_file%"
echo Calculating signatures... >>"%log_file%"

for /R "%work_dir%\eml_content" %%I in (*) do (
  if %%~zI lss %min_file_size% (
    echo %%~nxI - skipped >>"%log_file%"
  ) else (
    echo %%~nxI >>"%log_file%"
    "%sigtool_exe%" --md5 "%%I" >>"%sig_file%" 2>>&1
  )
)

rem Delete parsed content
rmdir /S/Q "%work_dir%\eml_content" 2>>"%log_file%"
del /F/S/Q "%work_dir%\*.*" 2>>"%log_file%"
echo ...done. >>"%log_file%"

rem Copying only last bases of signatures to ClamAV
echo. >>"%log_file%"
echo Copying signatures to ClamAV... >>"%log_file%"
xcopy /R/D/Y "%base_dir%\%sig_basename%.*" "%clamav_db%" >>"%log_file%" 2>>&1

echo. >>"%log_file%"
echo Finished: %date%-%time% >>"%log_file%"

goto :EOF


:rotate
rem Delete oldest sig.base and rename other
rem %1 - directory with files
rem %2 - base name of sig.files
rem %3 - ext. sig.files
rem %4 - max count of files (min - 1)

setlocal EnableDelayedExpansion

set sig_path=%1
set sig_path=%sig_path:"=%
set sig_name=%2
set sig_name=%sig_name:"=%
set sig_ext=%3
set sig_cnt=%4

del /F/S/Q "%sig_path%\%sig_name%_%sig_cnt%.%sig_ext%"
for /L %%i in (%sig_cnt%,-1,2) do (
  set /A prev_num=%%i-1
  rename "%sig_path%\%sig_name%_!prev_num!.%sig_ext%" "%sig_name%_%%i.%sig_ext%"
)
rename "%sig_path%\%sig_name%.%sig_ext%" "%sig_name%_1.%sig_ext%"

endlocal
goto :EOF
