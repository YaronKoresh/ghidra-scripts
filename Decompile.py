import os
import codecs
import re
from __main__ import currentProgram
scriptFolder = os.path.abspath(os.path.dirname(__file__))
mainFolder = os.path.join(scriptFolder,"..","..","..","..")
h = "#include <stdio.h>\n#include <stdlib.h>\n#include <assert.h>\n#include <complex.h>\n#include <ctype.h>\n#include <errno.h>\n#include <fenv.h> \n#include <float.h>\n#include <inttypes.h>\n#include <iso646.h>\n#include <limits.h>\n#include <locale.h>\n#include <math.h>\n#include <setjmp.h>\n#include <signal.h>\n#include <stdalign.h>\n#include <stdarg.h>\n#include <stdatomic.h>\n//#include <stdbit.h>\n#include <stdbool.h>\n//#include <stdckdint.h>\n#include <stddef.h>\n#include <stdint.h>\n#include <stdio.h>\n#include <stdlib.h>\n#include <stdnoreturn.h>\n#include <string.h>\n#include <tgmath.h>\n#include <threads.h>\n#include <time.h>\n#include <uchar.h>\n#include <wchar.h>\n#include <wctype.h>\n"
decompInterface = ghidra.app.decompiler.DecompInterface()
api = ghidra.program.flatapi.FlatProgramAPI(currentProgram,monitor)
decompInterface.openProgram(currentProgram)
api.analyzeAll(currentProgram)
funcsIter = currentProgram.getFunctionManager().getFunctions(False)
iter = iter(funcsIter)
decompiled = ""
for func in iter:
    decompileResults = decompInterface.decompileFunction(func, 30, api.getMonitor())
    if decompileResults.decompileCompleted():
        decompiledFunction = decompileResults.getDecompiledFunction()
        decompiled += "\n" + decompiledFunction.getC()
outPath = os.path.join(outFolder,name+".c")
out = codecs.open(outPath, "w","utf-8")
out.write(h+decompiled)
out.close()
