# RopDaemon

A fast, multithreaded, ROP-gadget semantics analyzer.

`RopDaemon` collects and analyses all the ROP gadgets in a program and assigns them a gadget category and multiple metadata, including:

* The address and the opcodes in the gadget
* The basic operation performed by the gadget, and the registers involved
* The registers invalidated/clobbered by the gadget
* The effect of the gadget on the stack pointer
* If the gadget accesses memory and how

Moreover, `RopDaemon` can reason on the gadgets by automatically crafting non-trivial ropchains.

## Gadget Categorization

| CLASS | DESCRIPTION | EXAMPLE |
| --- | --- | --- |
| LoadConst | Load constant value into a register | pop rax; ret |
| ClearReg | Set to zero a register | xor rax, rax; ret |
| MovReg | Copy value from a register to a register | mov rax, rcx; ret |
| UnOp | Unary arithmetic/logical oper. over a register | inc rax; ret |
| BinOp | Binary arithmetic/logical oper. over registers | add rax, rbx; ret |
| ReadMem | Read value from memory | mov rax, qword ptr [rcx + 8]; ret |
| WriteMem | Write value into memory | mov qword ptr [rcx + 8], rax; ret |
| ReadMemOp | Binary operation with memory input | add rax, qword ptr [rcx + 8]; ret |
| WriteMemOp | Binary operation with memory output | add qword ptr [rcx + 0x10], rax; ret |
| StackPtrOp | Alter stack pointer value | add rsp, 8; ret |
| Other | Any other operation | syscall; ret |

Gadgets are initially collected by [ropper](https://github.com/sashs/Ropper).
All valid gadgets are executed under [unicorn](https://www.unicorn-engine.org/) using random input values in the registers. This allows `RopDaemon` to collect the gadgets that are candidates for interesting operations. All the others are quickly discarded.

`RopDaemon` verifies only the interesting gadgets using the [angr](https://angr.io/) framework.

## Chain crafting

`RopDaemon` is able to craft non-trivial ropchains using graph based algorithms. It supports setting registers to fixed values, writing to memory, calling functions and syscalls.

It creates a graph based on gadgets dependencies to express the effect each gadget execution has on the registers/memory state, including registers that must be valid (since dereferenced) and registers clobbered by the gadget execution.
A query is then a simple visit on the graph.

## Install

``` shell
$ python3 setup.py install
```

## Usage

``` shell
$ ropd --help                                                                                                                                                                                           
usage: ropd [-h] [-c] [-v] [-e] [-d] [-j] [--stats] binary

This is RopDaemon, a fast rop-gadget compiler

positional arguments:
  binary         input binary

optional arguments:
  -h, --help     show this help message and exit
  -c, --collect  collect and categorize gadgets
  -v, --verify   formally verify collected gadgets
  -e, --execve   generate a ropchain to perform an execve("/bin/sh") syscall
  -d, --dump     dump gadgets file to a readable format
  -j, --json     dump gadgets file to json format
  --stats        statistics about verified gadgets
```

* Run `ropd -cv <binary>` to collect, verify the gadgets in `<binary>`.
  Collection and Verification phase have to be run once per binary. `RopDaemon` will create a `<binary>.collected` and `<binary>.verified` file to cache the results.
* Run `ropd -j <binary>` to dump a `json` file with all the verified gadgets for `<binary>`.
* Run `ropd -e <binary>` to produce an `execve("/bin/sh")` chain from `<binary>`.