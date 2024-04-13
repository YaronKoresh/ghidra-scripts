import os
import codecs
import re
import sys
import subprocess
from __main__ import currentProgram
from ghidra.program.database import ProgramAddressFactory
from ghidra.program.model.address import AddressSet
from ghidra.framework import ApplicationConfiguration
from ghidra.app.services import ProgramManager
from docking.widgets.filechooser import GhidraFile
from ghidra.program.model.lang import LanguageID
from ghidra.program.util import DefaultLanguageService, ProgramLocation
from ghidra.app.util import SymbolPath
from ghidra.app.util import NamespaceUtils
from java.io import File

scriptFolder = os.path.abspath(os.path.dirname(__file__))
mainFolder = os.path.join(scriptFolder,"..","..","..","..")
procFolder = os.path.join(mainFolder,"Ghidra","Processors")
radare2Folder = os.path.join(mainFolder,"radare2","bin")
outFolder = mainFolder
rabinPath = os.path.join(radare2Folder,"rabin2.exe")

disassembled = ""
disassembledData = ""
disassembledBss = ""

config = ApplicationConfiguration()
monitor = config.getTaskMonitor()

program = None
rng = None
api = None
path = None
fileSize = None
name = None
proc = None
file = None
entryPoint = None
lang = None
compilerSpec = None
arch = None
bits = None
endian = None
Addressor = None
programContext = None
memoryBlocks = None
memory = None
memoryStart = None
memoryView = None
listingObj = None
disassembled = None
disassembledData = None
disassembledBss = None
deps = [
    [ currentProgram, None ]
]
symbolName = [ "main" ]

def ResolveExternalFunction(fCode):
    global symbolName
    global program
    global rng
    global api
    global path
    global fileSize
    global name
    global proc
    global file
    global entryPoint
    global lang
    global compilerSpec
    global arch
    global bits
    global endian
    global Addressor
    global programContext
    global memoryBlocks
    global memory
    global memoryStart
    global memoryView
    global listingObj
    global disassembled
    global disassembledData
    global disassembledBss
    global deps

    externalLocation = None

    print("Searching: " + fCode)

    externalFuncs = program.getFunctionManager().getExternalFunctions()
    externalAddress = externalFuncs[0].getExternalLocation().getAddress()

    while externalAddress.isExternalAddress():
        code = ""
        bytes = iter(api.getBytes(externalAddress,8))
        for byte in bytes:
            code = hex(byte) + code
        while code.startswith('00'):
            code = code[2:]
        print(fCode + " <=> " + code)
        if code == fCode:
            externalLocation = program.getExternalManager().getExternalLocations(externalAddress)[0]
            break
        externalAddress = externalAddress.add(8)

    if externalLocation == None:
        print("No external function found!")
        return None
    else:
        print("External function: " + str(externalLocation))

    externalSymbol = externalLocation.getSymbol()
    libPath = program.getExternalManager().getExternalLibrary(externalLocation.getLibraryName()).getAssociatedProgramPath()
    projectData = state.getProject().getProjectData()
    libFile = projectData.getFile(libPath)
    externalProgram = libFile.getImmutableDomainObject(libFile, ghidra.framework.model.DomainFile.DEFAULT_VERSION, monitor)
    label = externalLocation.getLabel()
    symbolPath = SymbolPath(label)
    symbols = NamespaceUtils.getSymbols(symbolPath, externalProgram)

    sym = None
    for s in symbols:
        if s.isExternalEntryPoint():
            sym = s
            break

    if sym == None:
        print("No external symbol found!")
        return None
    else:
        print("External symbol: " + str(sym))

    loc = ProgramLocation( program, sym.getAddress() )
    fns = externalProgram.getFunctionManager().getFunctions(True)
    fn = None

    for f in fns:
        loc2 = ProgramLocation( externalProgram, f.getEntryPoint() )
        if loc == loc2:
            fn = f
            break

    if sym == None:
        print("External search: Failed")
        return None
    else:
        print("External search: OK")

    retProg = externalProgram
    retAddr = fn.getBody()

    dep = [
        retProg,
        retAddr
    ]

    deps.append(dep)

    symbolName.append( str(sym) )

def MemFix():
    global symbolName
    global program
    global rng
    global api
    global path
    global fileSize
    global name
    global proc
    global file
    global entryPoint
    global lang
    global compilerSpec
    global arch
    global bits
    global endian
    global Addressor
    global programContext
    global memoryBlocks
    global memory
    global memoryStart
    global memoryView
    global listingObj
    global disassembled
    global disassembledData
    global disassembledBss
    global deps

    for block in memoryBlocks:
        block.setWrite(False)

def Disassemble():
    global symbolName
    global program
    global rng
    global api
    global path
    global fileSize
    global name
    global proc
    global file
    global entryPoint
    global lang
    global compilerSpec
    global arch
    global bits
    global endian
    global Addressor
    global programContext
    global memoryBlocks
    global memory
    global memoryStart
    global memoryView
    global listingObj
    global disassembled
    global disassembledData
    global disassembledBss
    global deps

    api.start()
    api.analyzeAll(program)
    api.end(True)

    disassembled += "bits64\n"
    disassembled += "\nglobal main\n"
    disassembled += "\nsection .text\n"
    disassembled += "\nmain:\njmp " + entryPoint + "\n"

    api.start()
    for addr in iter(memoryView.getAddresses(True)):
        if addr.toString() == entryPoint:
            for block in memoryBlocks:
                if block.contains(addr):
                    api.disassemble(block.getStart())
                    break
            break
    api.end(True)

    refs = []
    instructionAddrs = []
    refsIndirectAddrs = []

    instructions = iter(listingObj.getInstructions(True))
    for i in instructions:
        cntx = i.getInstructionContext()
        addr = cntx.getAddress()
        codeUnit = listingObj.getCodeUnitAt(addr)
        _refs = codeUnit.getReferencesFrom()    
        codeUnitStr = str(codeUnit)
        for r in _refs:
            a = r.getToAddress()
            isData = r.getReferenceType().isData()
            isIndirect = r.getReferenceType().isIndirect()
            if isData:
                refs.append(r)
            elif isIndirect:
                refs.append(r)
                refsIndirectAddrs.append(a.toString())

        codeUnitStr = codeUnitStr.lower()
        codeUnitStr = codeUnitStr.replace("lab_","LAB_")
        codeUnitStr = codeUnitStr.replace("[0x","[LAB_")
        codeUnitStr = codeUnitStr.replace(" ptr "," ")
        codeUnitStr = codeUnitStr.replace("xmmword "," ")

        check1 = re.findall(r'\.lock?', codeUnitStr)
        if len(check1) > 0:
            codeUnitStr = "lock " + codeUnitStr.replace(".lock","")

        check2 = re.findall(r'\.rep[n]?[ze]?', codeUnitStr)
        if len(check2) > 0:
            codeUnitStr = check2[0][1:] + " " + codeUnitStr.replace(check2[0],"")

        check3 = re.findall(r'stos[bwdq]|lods[bwdq]', codeUnitStr)
        if len(check3) > 0:
            if check3[0] == "lodsb":
                reg = codeUnitStr.replace("lodsb ","").replace("rep ","")
                size = "al"
                codeUnitStr = "mov " + size + ",[" + reg + "]\ninc " + reg
            elif check3[0] == "lodsw":
                reg = codeUnitStr.replace("lodsw ","").replace("rep ","")
                size = "ax"
                codeUnitStr = "mov " + size + ",[" + reg + "]\ninc " + reg
                codeUnitStr += "\ninc " + reg
            elif check3[0] == "lodsd":
                reg = codeUnitStr.replace("lodsd ","").replace("rep ","")
                size = "eax"
                codeUnitStr = "mov " + size + ",[" + reg + "]\ninc " + reg
                codeUnitStr += "\ninc " + reg
                codeUnitStr += "\ninc " + reg
                codeUnitStr += "\ninc " + reg
            elif check3[0] == "lodsq":
                reg = codeUnitStr.replace("lodsq ","").replace("rep ","")
                size = "rax"
                codeUnitStr = "mov " + size + ",[" + reg + "]\ninc " + reg
                codeUnitStr += "\ninc " + reg
                codeUnitStr += "\ninc " + reg
                codeUnitStr += "\ninc " + reg
                codeUnitStr += "\ninc " + reg
                codeUnitStr += "\ninc " + reg
                codeUnitStr += "\ninc " + reg
                codeUnitStr += "\ninc " + reg
            elif check3[0] == "stosb":
                reg = codeUnitStr.replace("stosb ","").replace("rep ","")
                size = "al"
                codeUnitStr = "mov [ss:" + reg + "]," + size + "\ninc " + reg
            elif check3[0] == "stosw":
                reg = codeUnitStr.replace("stosw ","").replace("rep ","")
                size = "ax"
                codeUnitStr = "mov [ss:" + reg + "]," + size + "\ninc " + reg
                codeUnitStr += "\ninc " + reg
            elif check3[0] == "stosd":
                reg = codeUnitStr.replace("stosd ","").replace("rep ","")
                size = "eax"
                codeUnitStr = "mov [ss:" + reg + "]," + size + "\ninc " + reg
                codeUnitStr += "\ninc " + reg
                codeUnitStr += "\ninc " + reg
                codeUnitStr += "\ninc " + reg
            elif check3[0] == "stosq":
                reg = codeUnitStr.replace("stosq ","").replace("rep ","")
                size = "rax"
                codeUnitStr = "mov [ss:" + reg + "]," + size + "\ninc " + reg
                codeUnitStr += "\ninc " + reg
                codeUnitStr += "\ninc " + reg
                codeUnitStr += "\ninc " + reg
                codeUnitStr += "\ninc " + reg
                codeUnitStr += "\ninc " + reg
                codeUnitStr += "\ninc " + reg
                codeUnitStr += "\ninc " + reg

        check4 = re.findall(r'scas[bwdq]|ins[bwdq]|movs[bwdq]', codeUnitStr)
        if len(check4) > 0:
            codeUnitStr = check4[0]

        check5 = re.findall( r' LAB_[0-9a-f]+' , codeUnitStr )
        if len(check5) > 0:
            codeUnitStr = codeUnitStr.replace(check5[0], " [" + check5[0][1:] + "]" )

        check6 = re.findall(r'\[LAB_[0-9a-f]{1,7}\]|\[LAB_[0-9a-f]{1,7} ',codeUnitStr)
        if len(check6) > 0:
            codeUnitStr = codeUnitStr.replace( "LAB_" , "0x" )

        codeUnitStr = codeUnitStr.replace("[[","[")
        codeUnitStr = codeUnitStr.replace("]]","]")

        check7 = re.findall( r'call 0x[0-9a-f]{8,}|j(mp|[n]?[zcsegl]{1,2}) 0x[0-9a-f]{8,}',codeUnitStr)
        if len(check7) > 0:
            codeUnitStr = codeUnitStr.replace( "0x" , "LAB_" )

        disassembled += "\n; " + codeUnit.getMinAddress().toString() + " -> " + codeUnit.getMaxAddress().toString()
        disassembled += "\nLAB_"+addr.toString() + ":\n" + codeUnitStr + "\n"
        instructionAddrs.append(addr.toString())

    shortLabels = []

    disassembled2 = disassembled.split("\n")
    disassembled3 = []
    currentMemoryAddress = ""
    firstMemoryAddress = ""
    for line in disassembled2:
        jumping = re.findall(r'(call|j(mp|[n]?[zcsegl]{1,2})) ([dq]?word|byte) (\[LAB_[0-9a-f]+\])', line)
        if line.startswith("; "):
            currentMemoryAddress = re.findall( r'[0-9a-f]+', line )[0]
            if firstMemoryAddress == "":
                firstMemoryAddress = currentMemoryAddress
        if len(jumping) == 0:
            disassembled3.append(line)
        else:
            stringAddress = re.findall(r'LAB_[0-9a-f]+', ' '.join([str(x) for x in jumping[0]]))[0].replace("LAB_","")
            if stringAddress in instructionAddrs:
                disassembled3.append(line)
            elif stringAddress in refsIndirectAddrs:
                oldAddress = Addressor.getAddress(stringAddress)
                newAddress = ""
                newAddressArr = []
                newAddressBytesIter = iter(api.getBytes(oldAddress,8))
                for byt in newAddressBytesIter:
                    if int(byt) < 0:
                        byt = byt & (2**bits-1)
                    byt = hex(byt).replace("0x","").replace("L","")
                    byt = byt[len(byt)-2:]
                    newAddress = byt.zfill(2) + newAddress
                while newAddress.startswith('0'):
                    newAddress = newAddress[1:]
                oldLabel = "LAB_" + stringAddress
                newLabel = "LAB_" + newAddress
		if len(newLabel) < 12:
                    shortLabels.append(newLabel)
                line = line.replace(oldLabel,newLabel)
                disassembled3.append(line)
            else:
                disassembled3.append("; "+line)

    disassembled = "\n".join(disassembled3)

    disassembledData += "\nsection .data\n"

    lnks = []

    for ref in refs:
        addr = ref.getToAddress().toString()
        if addr not in lnks:
                lnks.append(addr)

    bsses = []
    for lnk in lnks:
        if lnk in instructionAddrs:
            continue
        addr = Addressor.getAddress(lnk)
        label = "LAB_" + lnk
        if memoryView.contains(addr):
            dataIter = iter(api.getBytes(addr,fileSize))
            data = []
            zerosCounter = 0
            for di in dataIter:
                if int(di) == 0:
                    data.append("00h")
                    zerosCounter += 1
                    if zerosCounter > 2:
                        break
                    continue
                if int(di) < 0:
                    di = di & (2**bits-1)
                di = hex(di).replace("0x","").replace("L","")
                di = di[len(di)-2:]
                data.append("0x"+di.zfill(2))
            data = ",".join(data)
            while data.endswith(',00h'):
                data = data[:-4]
            disassembledData += "\n" + label + ": db " + data + "\n"
        else:
            if lnk not in bsses:
                bsses.append(lnk)

    disassembledBss += "\nsection .bss\n"

    for lnk in bsses:
        if lnk in instructionAddrs:
            continue
        if len(re.findall(r'Stack', lnk)) == 0:
            name = "LAB_" + lnk
            disassembledBss += "\n" + name + ": resb 16\n"

    for shortLabel in shortLabels:
        extFunctionCode = shortLabel[4:]
        ResolveExternalFunction(extFunctionCode)
        disassembled += "\n; External Code..."
        depPath = deps[ len(deps)-1 ][0].getExecutablePath().lstrip("/")
        depName = os.path.splitext(os.path.basename(depPath))[0]
        disassembled += "\n" + shortLabel + ":\n%include '" + depName + "_" + symbolName[ len(symbolName)-1 ] + "'\n"

def Prepare():
    global symbolName
    global program
    global rng
    global api
    global path
    global fileSize
    global name
    global proc
    global file
    global entryPoint
    global lang
    global compilerSpec
    global arch
    global bits
    global endian
    global Addressor
    global programContext
    global memoryBlocks
    global memory
    global memoryStart
    global memoryView
    global listingObj
    global disassembled
    global disassembledData
    global disassembledBss
    global deps

    program = deps[0][0]
    rng = deps[0][1]

    disassembled = ""
    disassembledData = ""
    disassembledBss = ""

    api = ghidra.program.flatapi.FlatProgramAPI(program,monitor)

    path = program.getExecutablePath().lstrip("/")
    fileSize = int(os.path.getsize(path))
    print("Size: " + str(fileSize) + " bytes")
    name = "code"
    if program != currentProgram:
        name = os.path.splitext(os.path.basename(path))[0]
    print("Input: " + path)

    proc = subprocess.Popen([ rabinPath, "-e", path ], stdout=subprocess.PIPE)

    path = os.path.join(outFolder,os.path.basename(path))
    file = File(path)
    path = file.getAbsolutePath()

    (entryPoint, err) = proc.communicate()
    entryPoint = re.findall(r'0x[0-9a-fA-F]+', entryPoint)[0].replace("0x","LAB_")

    print("Start: " + entryPoint)

    lang = program.getLanguage()
    compilerSpec = program.getCompilerSpec()
    arch = re.findall(r'[^:]+:', str(program.getLanguageID()))[0][0:-1]
    bits = int(re.findall(r':\d+:', str(program.getLanguageID()))[0][1:-1])
    endian = "LE"
    if str(program.getLanguageID()).replace(":BE:","") != str(program.getLanguageID()):
        endian = "BE"

    print("Arch: " + arch + " " + endian + " (" + str(bits) + " bit)")

    Addressor = ProgramAddressFactory(lang,compilerSpec)
    programContext = ghidra.program.util.ProgramContextImpl(lang)
    memoryBlocks = api.getMemoryBlocks()

    memory = program.getMemory()
    memoryStart = program.getMinAddress()
    memoryView = memory.getAllInitializedAddressSet()

    if rng != None:
        memory = rng
        memoryStart = rng.getMinAddress()
        memoryView = rng

    listingObj = program.getListing()

def Export():
    global symbolName
    global program
    global rng
    global api
    global path
    global fileSize
    global name
    global proc
    global file
    global entryPoint
    global lang
    global compilerSpec
    global arch
    global bits
    global endian
    global Addressor
    global programContext
    global memoryBlocks
    global memory
    global memoryStart
    global memoryView
    global listingObj
    global disassembled
    global disassembledData
    global disassembledBss
    global deps

    assemblyContent = disassembled + disassembledData + disassembledBss
    lowOut = os.path.join( outFolder, name + "_" + symbolName[0] + ".asm" )
    print("Output: " + os.path.normpath(lowOut))
    low = codecs.open(lowOut, "w","utf-8")
    low.write(assemblyContent)
    low.close()

def main():
    global symbolName
    global program
    global rng
    global api
    global path
    global fileSize
    global name
    global proc
    global file
    global entryPoint
    global lang
    global compilerSpec
    global arch
    global bits
    global endian
    global Addressor
    global programContext
    global memoryBlocks
    global memory
    global memoryStart
    global memoryView
    global listingObj
    global disassembled
    global disassembledData
    global disassembledBss
    global deps

    while len(deps) > 0:
        Prepare()
        MemFix()
        Disassemble()
        Export()

        del deps[0]
        del symbolName[0]

    return 0

if __name__ == "__main__":
    main()
