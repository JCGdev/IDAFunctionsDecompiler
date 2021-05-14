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

>MD5 --> `f1acc89e337054c811b70022a6eca499`

>Sha1 --> `b925fbcb32a2f34366ab66610b17fce18d902bd5`

>Sha256 --> `7967f64443b68b69c953770782511df12b73b15b23abb684b57348a023718de7`

## Setup

***Change output path***

`Edit "outputPath" variable from the script, and specify the folder where pseudocode will be stored`

Example:

`outputPath = "C:\\Users\Juanjo\\Desktop\\test"`

![](example.gif)

## Docs

[IDA API](https://www.hex-rays.com/products/ida/support/idapython_docs/)

[IDA 7.4 Newer API changes](https://www.hex-rays.com/products/ida/support/ida74_idapython_no_bc695_porting_guide.shtml)


