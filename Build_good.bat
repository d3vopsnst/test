rem @echo off
rem @set DNI_BIN=C:\Program Files (x86)\dotNetInstaller\bin
rem 
rem ::Project Files
rem rem @set Project_Dir=%CD%
rem @set Project_XML=configuration.xml
rem @set Project_EXE=MedES Server 2016 PCI.exe
rem @set Project_Banner=..\shared\BDbanner.bmp
rem @set Project_Icon=..\shared\BDIcon.ico
rem 
rem @echo Building suite installer...
rem cd %Project_Dir%
rem MD "%Project_Dir%\release"
rem "%DNI_BIN%\InstallerLinker.exe" /c:"%Project_Dir%\%Project_XML%" /Output:"%Project_Dir%\release\%Project_EXE%" /Template:"%DNI_BIN%\dotNetInstaller.exe" /Banner:"%Project_Dir%\%Project_Banner%" /Icon:"%Project_Dir%\%Project_Icon%" /v+
rem 
rem cls
rem IF %ERRORLEVEL%==0 (GOTO BUILD_OK) ELSE (GOTO BUILD_ERROR)
rem goto End
rem 
rem :BUILD_ERROR
rem echo Error building dotNetInstaller wrapper!
rem EXIT /B 1
rem goto End
rem 
rem :BUILD_OK
rem echo Build complete
rem goto End
rem 
rem :End

"C:\Program Files (x86)\dotNetInstaller\bin\InstallerLinker.exe" /c:"C:\Users\Luis\OneDrive - NearShore Technology\BD\PCI\AD Migration\configuration.xml" /Output:"C:\Users\Luis\OneDrive - NearShore Technology\BD\PCI\AD Migration\AD Migration.exe" /Template:"C:\Program Files (x86)\dotNetInstaller\bin\dotNetInstaller.exe" /Banner:"C:\Users\Luis\OneDrive - NearShore Technology\BD\PCI\shared\BDBanner.bmp" /Icon:"C:\Users\Luis\OneDrive - NearShore Technology\BD\PCI\shared\NST.ico"