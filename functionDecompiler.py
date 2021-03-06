# JCGdec functions decompiler for IDA 7.5
# Hexrays decompiler and IDAPython plugins are needed

import idautils
import idaapi 
import idc
import ida_hexrays
import ida_lines
import ida_funcs
import ida_kernwin
import ida_ida

import sys
import os
import shutil

outputPath = "C:\\Users\Juanjo\\Desktop\\test"	# PATH MUST BE EDITED

def checkPath():
	if not os.path.exists(outputPath):
		os.mkdir(outputPath)
	else:
		shutil.rmtree(outputPath)
		os.mkdir(outputPath)

def initHexraysPlugin():
	if not ida_hexrays.init_hexrays_plugin():
		errorLogger(f"[Error] hexrays (version %s) failed to init \n" % ida_hexrays.get_hexrays_version())
		return idaapi.PLUGIN_SKIP
	else:	
		IDAConsolePrint(f"[*] Hex-rays version %s has been detected \n" % ida_hexrays.get_hexrays_version())

def listFunctions():
	functionList=[]

	for func in idautils.Functions():
    		functionList.append(func)

	return functionList

def decompileFunctions(functionList):
	
	functionCounter = 1
	IDAConsolePrint("[!] Process started [!] \n")
		

	for func in listFunctions():
		
		funcName = idc.get_func_name(func)
		appendToHashmap(funcName, parseIlegalChars(funcName))
	
		try:
			IDAConsolePrint(f"[{functionCounter}] Decompiling --> {funcName} \n")
			decompiledFunc = ida_hexrays.decompile(func);
			pseudoCodeOBJ = decompiledFunc.get_pseudocode()
			
			dumpPseudocode(pseudoCodeOBJ, funcName)
			functionCounter += 1

		except:
			exceptionLogger(funcName)
			functionCounter -= 1			

	IDAConsolePrint(f"[!] Successfully decompiled %s functions! [!]" % str(functionCounter - 1))

def dumpPseudocode(pseudoCodeOBJ, funcName):
	with open(os.path.join(outputPath, parseIlegalChars(funcName)), "a") as f:
		f.write(f"// {funcName} \n \n")
		for lineOBJ in pseudoCodeOBJ:
			f.write(ida_lines.tag_remove(lineOBJ.line) + "\n")

def IDAConsolePrint(message):
	ida_kernwin.msg(message)

def exceptionLogger(funcName):
	IDAConsolePrint(f"[%s] --> FAILED DECOMPILING \n" % funcName)
	with open(os.path.join(outputPath, "0 - ERROR_LOG.txt"), "a") as f:
		f.write(f"[%s] --> FAILED DECOMPILING \n" % funcName)
		f.write(f"[Parsed func name]: %s \n" % parseIlegalChars(funcName))
		f.write(f"[Absolute path]: %s \n" % os.path.join(outputPath, parseIlegalChars(funcName)))
		f.write(f"[Exception info]: %s \n \n" % str(sys.exc_info()))

def errorLogger(message):
	IDAConsolePrint(message)
	with open(os.path.join(outputPath, "0 - ERROR_LOG.txt"), "a") as f:
		f.write(message + "\n")	

def parseIlegalChars(stringToParse):
	ilegalChars = ("/", "\\", ":", "<", ">", "|", "?", ",", ".", "&")
	parsedString = stringToParse	

	for char in ilegalChars:
		if char in stringToParse:
			parsedString = stringToParse.replace(char, "-")
	return parsedString


def appendToHashmap(funcName, parsedFuncName):
	try:
		with open(os.path.join(outputPath, "1 - nameMap.txt"), "a") as f:
			f.write(f"{funcName} : {parsedFuncName} \n")
	except:
		exceptionLogger(funcName)

def main():

	checkPath()
	initHexraysPlugin()	
	functionList = listFunctions()

	decompileFunctions(functionList)


if __name__ == "__main__":
	main()
