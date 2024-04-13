import os
import codecs
import re
from __main__ import currentProgram
scriptFolder = os.path.abspath(os.path.dirname(__file__))
mainFolder = os.path.join(scriptFolder,"..","..","..","..")
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
outPath = os.path.join(mainFolder,name+".c")
out = codecs.open(outPath, "w","utf-8")
out.write(decompiled)
out.close()
