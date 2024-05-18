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

doskey python=C:\users\%username%\AppData\Local\Programs\Python\Launcher\py.exe $*

python .\emsdk\emsdk.py install latest
python .\emsdk\emsdk.py activate latest
python .\emsdk\emsdk.py update
python .\emsdk\emsdk_env.py

python .\emsdk\upstream\emscripten\emcc.py -v
python .\emsdk\upstream\emscripten\emcc.py -O0 -Wno-error=implicit-function-declaration -Wno-error=int-conversion "!origin4!" -o "!origin5!"

python -m http.server

pause