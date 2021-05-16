# IDAFunctionsDecompiler

An IDAPython script to decompile all the functions of a binary and dump the pseudocode 

## Table of contents
* [General info](#general-info)
* [Checksums](#checksums)
* [Setup](#setup)
* [Docs](#Docs)


## General info

>- Get the decompiled pseudocode of every function in a binary, using IDA 7.5 and it's API

>- IDAPython plugin and Hexrays decompiler needed! 

## Checksums

gofileUploader.py hashes

>MD5 --> `4c8aedeac86ab5c903930991de7205ad`

>Sha1 --> `4ca6176c982fb5fb3e0788844a888072c33f722b`

>Sha256 --> `853e2b5e108c00cb9eea040c85fd50147630cffdcb311566919b60582029341f`

## Setup

***Change output path***

`Edit "outputPath" variable from the script, and specify the folder where pseudocode will be stored`

Example:

`outputPath = "C:\\Users\Juanjo\\Desktop\\test"`

![](example.gif)

## Docs

[IDA API](https://www.hex-rays.com/products/ida/support/idapython_docs/)

[IDA 7.4 Newer API changes](https://www.hex-rays.com/products/ida/support/ida74_idapython_no_bc695_porting_guide.shtml)


