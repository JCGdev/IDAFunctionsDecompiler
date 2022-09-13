# IDAFunctionsDecompiler

An IDAPython script to decompile all the functions of a binary and dump the pseudocode 

## Table of contents
* [General info](#general-info)
* [Checksums](#checksums)
* [Setup](#setup)
* [Docs](#Docs)


## General info

>- Get the decompiled pseudocode of every function in an executable.

>- Tested on IDA 7.5

>- IDAPython plugin and Hexrays decompiler needed! 

## Checksums

`functionDecompiler.py` hashes

>MD5 --> `e4dcf2dee23bb7d39172441b93e88925`

>Sha1 --> `5cf1f74791581dbe10e13d848bf80ea9041c7740 `

>Sha256 --> `537683666fa696b4b34bfaed910ce8a913f15e0b96c8d49ea523e848b4c16b28 `

## Setup

***Change output path***

`Edit "outputPath" variable from the script, and specify the path where the pseudocode will be stored`

Example:

`outputPath = "C:\\Users\Juanjo\\Desktop\\test"`

![](example.gif)

## Docs

[IDA API](https://www.hex-rays.com/products/ida/support/idapython_docs/)

[IDA 7.4 Newer API changes](https://www.hex-rays.com/products/ida/support/ida74_idapython_no_bc695_porting_guide.shtml)


