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
ea = ida_ida.inf_get_min_ea()

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
		ida_kernwin.msg(f"Hex-rays version %s has been detected \n" % ida_hexrays.get_hexrays_version())

def listFunctions():
	functionList=[]

	for func in Functions(idc.get_segm_start(ea), idc.get_segm_end(ea)):
    		functionList.append(func)

	return functionList

def decompileFunctions(functionList):
	
	for func in listFunctions():
		
		funcName = idc.get_func_name(func)
		parsedFuncName = parseIlegalChars(funcName)

		try:
			
			decompiledFunc = ida_hexrays.decompile(func);
			pseudoCodeObj = decompiledFunc.get_pseudocode()

			ida_kernwin.msg(f"Process started with --> {funcName} \n")

			with open(os.path.join(outputPath, parsedFuncName), "a") as f:
				f.write("// " + funcName + "\n \n")
				for lineObj in pseudoCodeObj:
					f.write(ida_lines.tag_remove(lineObj.line))
		except:
			errorLogger(f"[%s] --> FAILED DECOMPILING \n" % funcName)

def errorLogger(message):
	ida_kernwin.msg(message)
	with open(os.path.join(outputPath, "0 - ERROR_LOG.txt"), "a") as f:
		f.write(message + "\n")

def parseIlegalChars(stringToParse):
	ilegalChars = ("/", "\\", ":", "<", ">", "|", "?", ",", ".", "&")
	parsedString = stringToParse	

	for char in ilegalChars:
		if char in stringToParse:
			parsedString = stringToParse.replace(char, "-")
	return parsedString

def main():

	checkPath()
	initHexraysPlugin()	
	functionList = listFunctions()

	decompileFunctions(functionList)


if __name__ == "__main__":
	main()
