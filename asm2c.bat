@echo off
setlocal ENABLEDELAYEDEXPANSION

set "dp=%~dp0"
cd !dp!

set "pth=%1"
for %%a in ("!pth!") do set "name=%~n1"

if "!pth!"=="" (
	set "pth=!dp!code.asm"
	set "name=code"
)

set "origin1=!dp!!name!.asm"
set "origin2=!dp!!name!.obj"
set "origin3=!dp!!name!.exe"
set "origin4=!dp!!name!.c"
set "origin5=!dp!!name!.html"

.\nasm\nasm.exe -f win64 "!origin1!"
.\linker\link.exe /entry:main /subsystem:windows /machine:x64 /LARGEADDRESSAWARE:NO /fixed "!origin2!"
.\retdec\bin\retdec-decompiler.exe -o "!origin4!" "!origin3!"

echo int main(){ return entry_point(); } >> "!origin4!"

del "!dp!!name!.config.json"
del "!dp!!name!.bc"
del "!dp!!name!.dsm"
del "!dp!!name!.ll"
del "!dp!!name!-unpacked"
del "!origin2!"
del "!origin3!"

pause