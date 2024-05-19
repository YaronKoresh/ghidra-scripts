# Ghidra installation:
* Install [Visual C++](https://learn.microsoft.com/en-us/cpp/windows/latest-supported-vc-redist#latest-microsoft-visual-c-redistributable-version).
* Install [Python](https://python.org/downloads).
* Install Java [JRE](https://java.com/en/download/windows_manual.jsp) & [JDK](https://oracle.com/il-en/java/technologies/downloads).
* Install [Ghidra](https://github.com/NationalSecurityAgency/ghidra/releases/latest).

# RetDec (by Avast) installation:
* Install [Graphviz](https://graphviz.org/download).
* Put a "retdec" directory, inside Ghidra root folder, and fill it with a copy of [RetDec decompiler](https://github.com/avast/retdec/releases/latest).
* Extract [UPX Packer](https://github.com/upx/upx/releases/latest) & put the main executable inside retdec/bin folder.

# Redare2 installation:
* Put a "radare2" directory, inside Ghidra root folder, and fill it with a copy of [Radare2 software](https://github.com/radareorg/radare2/releases/latest).

# Nasm installation:
* Put a "nasm" directory, inside Ghidra root folder, and fill it with a copy of [NASM assembler](https://nasm.us).

# Emscripten installation:
* Put a "emsdk" directory, inside Ghidra root folder, and fill it with a copy of [Emscripten C-to-Javascript converter](https://github.com/emscripten-core/emsdk/archive/refs/heads/main.zip). You do not need to install Emscripten manually. My batch scripts are doing it automatically.

# Linkers installation:
* Put a "linker" directory, inside Ghidra root folder, and fill it with a copy of "linkers.zip".

# Python scripts installation:
* Put any *.py script, inside: "Ghidra/Features/Python/ghidra_scripts" (inside Ghidra root folder).
* You will see these *.py scripts, through the "code browser" tool, from "scripts" window of Ghidra.

# Batch scripts installation:
* Put any *.bat script, inside Ghidra root folder.

# Finally, using the new reversing toolset:
1. Import your software, with all its local/system direct/indirect dependencies (can be done automatically, during import, using "options" button).
2. Inside "scripts" window, double click on the name of the needed python script.
3. Go into the root folder, to see the results.
4. Use any batch script to manipulate the results, according to your needs.
