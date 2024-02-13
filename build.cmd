@echo off
rem SPDX-License-Identifier: MIT
rem Copyright (C) 2019-2021 WireGuard LLC. All Rights Reserved.

setlocal enabledelayedexpansion
set BUILDDIR=%~dp0
set PATH=%BUILDDIR%.deps\llvm-mingw\bin;%BUILDDIR%src;%PATH%
set PATHEXT=.exe
cd /d %BUILDDIR% || exit /b 1

if exist .deps/prepared goto :build
:installdeps
	rmdir /s /q .deps 2> NUL
	mkdir .deps || goto :error
	cd  .deps || goto :error
	call :download llvm-mingw-msvcrt.zip https://download.wireguard.com/windows-toolchain/distfiles/llvm-mingw-20201020-msvcrt-x86_64.zip 2e46593245090df96d15e360e092f0b62b97e93866e0162dca7f93b16722b844 || goto :error
	call :download wireguard-nt.zip https://download.wireguard.com/wireguard-nt/wireguard-nt-0.10.1.zip 772c0b1463d8d2212716f43f06f4594d880dea4f735165bd68e388fc41b81605 || goto :error
	copy /y NUL prepared > NUL || goto :error
	cd .. || goto :error

:build
	call :build_plat x64 x86_64 amd64 || goto :error
	call :build_plat x86 i686 386 || goto :error
	call :build_plat arm64 aarch64 arm64 || goto :error
	
:success
	echo [+] Success
	exit /b 0

:download
	echo [+] Downloading %1
	curl --retry 3 -#fLo %1 %2 || exit /b 1
	echo [+] Verifying %1
	for /f %%a in ('CertUtil -hashfile %1 SHA256 ^| findstr /r "^[0-9a-f]*$"') do if not "%%a"=="%~3" exit /b 1
	echo [+] Extracting %1
	tar -xf %1 %~4 || exit /b 1
	echo [+] Cleaning up %1
	del %1 || exit /b 1
	goto :eof

:build_plat
	mkdir %1 >NUL 2>&1
	echo [+] Assembling resources %1
	%~2-w64-mingw32-windres -I ".deps\wireguard-nt\bin\%~1" -DWIREGUARD_VERSION_ARRAY=0.5.3 -DWIREGUARD_VERSION_STR=0.5.3 -i src/wincompat/resources.rc -o "src/wincompat/resources_%~3.syso" -O coff -c 65001 || exit /b %errorlevel%
	echo [+] Building command line tools %1
	del src\*.exe src\*.o src\wincompat\*.o src\wincompat\*.lib 2> NUL
	set LDFLAGS=-s
	make --no-print-directory -C src PLATFORM=windows CC=%~2-w64-mingw32-gcc WINDRES=%~2-w64-mingw32-windres V=1 RUNSTATEDIR= SYSTEMDUNITDIR= -j%NUMBER_OF_PROCESSORS% || exit /b 1
	move /Y src\wg.exe "%~1\awg.exe" > NUL || exit /b 1
	goto :eof

:error
	echo [-] Failed with error #%errorlevel%.
	cmd /c exit %errorlevel%


