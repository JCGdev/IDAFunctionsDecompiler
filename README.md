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

>MD5 --> `fcc098df7e6df52aa057f60f7688ddb9`

>Sha1 --> `b5037792a27ed5a35082f0f3d98af3491cccc828`

>Sha256 --> `2702090aedb8dd088bcb01fe7ffc8ad9b4568c40148202590f1739e73211bf86`

## Setup

***Change output path***

`Edit "outputPath" variable from the script, and specify the folder where pseudocode will be stored`

Example:

`outputPath = "C:\\Users\Juanjo\\Desktop\\test"`

![](example.gif)

## Docs

[IDA API](https://www.hex-rays.com/products/ida/support/idapython_docs/)

[IDA 7.4 Newer API changes](https://www.hex-rays.com/products/ida/support/ida74_idapython_no_bc695_porting_guide.shtml)


