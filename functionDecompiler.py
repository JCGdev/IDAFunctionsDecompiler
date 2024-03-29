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

# PATH MUST BE SETTED UP
# Windows users must escape reverse slash in path: \\
outputPath: str = ""
functionsPath: str = os.path.join(outputPath, "functions")

if outputPath == "":
	ErrorLogger("'outputPath' variable has not been setted up!")
	sys.exit(1)


# --- function definitions ---


def main() -> None:
	checkOutputPath()
	initHexraysPlugin()	

	IDAConsolePrint("[!] Starting... [!] \n")

	global functionsPath
	realAndSanitizedFunctionNameMapping: dict = {}
	functionCounter: int = 1

	for func in idautils.Functions():
		funcName: str = idc.get_func_name(func)
		sanitizedFuncName = parseIlegalChars(funcName)
		
		# Filenames must be sanitized. Because of that, this mapping may help
		# to identify the real function name when needed
		realAndSanitizedFunctionNameMapping[funcName] = sanitizedFuncName

		try:
			IDAConsolePrint(f"[{functionCounter}] Decompiling --> {funcName} ({functionsPath}) \n")

			pseudoCodeOBJ: ida_pro.strvec_t = decompileFunction(func)
			pseudoCodeString = pseudoCodeObjToString(pseudoCodeOBJ)


			dumpPseudocodeToRespectiveFile(pseudoCodeString, funcName)
			functionCounter += 1
			del pseudoCodeOBJ

		except Exception as e:
			exceptionLogger(e)
			functionCounter -= 1			

	IDAConsolePrint(f"[!] Successfully decompiled %s functions! [!]" % str(functionCounter - 1))
	dumpToFileRealAndSanitizedFunctionNamesMapping(realAndSanitizedFunctionNameMapping)


def checkOutputPath() -> None:
	if not os.path.exists(outputPath):
		os.mkdir(outputPath)
		os.mkdir(functionsPath)
	else:
		shutil.rmtree(outputPath)
		os.mkdir(outputPath)
		os.mkdir(functionsPath)


def initHexraysPlugin() -> None:
	if not ida_hexrays.init_hexrays_plugin():
		errorLogger(f"[Error] hexrays (version %s) failed to init \n" % ida_hexrays.get_hexrays_version())
		sys.exit(1)
	else:	
		IDAConsolePrint(f"[*] Hex-rays version %s has been detected \n" % ida_hexrays.get_hexrays_version())


def IDAConsolePrint(message: str) -> None:
	ida_kernwin.msg(message)


def parseIlegalChars(stringToParse: str) -> str:
	ilegalChars: tuple = ("/", "\\", ":", "<", ">", "|", "?", ",", ".", "&")
	parsedString: str = stringToParse	

	for char in ilegalChars:
		if char in stringToParse:
			parsedString = stringToParse.replace(char, "-")
	return parsedString


def decompileFunction(func: int) -> ida_pro.strvec_t:
	try:
		decompiledFunc: ida_hexrays.cfuncptr_t = ida_hexrays.decompile(func);
		pseudoCodeOBJ: ida_pro.strvec_t = decompiledFunc.get_pseudocode()

		return pseudoCodeOBJ

	except Exception as e:
		raise e
	

def pseudoCodeObjToString(pseudoCodeOBJ: ida_pro.strvec_t) -> str:
	convertedObj: str = ""

	for lineOBJ in pseudoCodeOBJ:
		convertedObj += (ida_lines.tag_remove(lineOBJ.line) + "\n")

	return convertedObj


def dumpPseudocodeToRespectiveFile(pseudoCode: str, filename: str) -> None:
	global functionsPath
	sanitizedFilename: str = parseIlegalChars(filename)

	with open(os.path.join(functionsPath, sanitizedFilename), "a") as f:
		f.write(pseudoCode)
		


def dumpToFileRealAndSanitizedFunctionNamesMapping(mapping: dict) -> None:

	try:
		with open(os.path.join(outputPath, "1 - nameMap.txt"), "a") as f:
			for key in mapping:
				f.write(f"{key} : {mapping[key]} \n")
	except Exception as e:
		exceptionLogger(e)


def exceptionLogger(exception: str) -> None:
	IDAConsolePrint(f"[EXCEPTION]:'%s' \n" % str(exception))
	with open(os.path.join(outputPath, "0 - ERROR_LOG.txt"), "a") as f:
		f.write(f"[EXCEPTION]:'%s' \n" % str(exception))
		f.write(f"[Exception info]: %s \n \n" % str(sys.exc_info()))


def errorLogger(message: str) -> None:
	IDAConsolePrint(message)
	with open(os.path.join(outputPath, "0 - ERROR_LOG.txt"), "a") as f:
		f.write(message + "\n")	


if __name__ == "__main__":
	main()
