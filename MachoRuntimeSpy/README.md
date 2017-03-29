## MachoRuntimeSpy

runtime spy

**In development...**

## Demo

```
jmpews at Jmp in ~/Desktop/rtspy/MachoRuntimeSpy (master●) (normal)
λ : sudo ./rtspy-mac
Password:
--------------------------------------------------------------
RTspy - macOS/IOS (1.0.0) - by jmpews@gmail.com
--------------------------------------------------------------
>> attach 79336
[*] macho load at 0x10da10000
[*] start dump macho:
[*] Arch-64
[*] string table addr: 0x10da12278
[*] symbol table addr: 0x10da12278
[*] dyld path: /usr/lib/dyld.
[*] start dump macho:
[*] Arch-fat
[*] start dump macho:
[*] Arch-64
[*] __TEXT segment vm_addr: 0x0
[!] only support x86_64.
[*] start dyld search range(0x10da13000, 0x11da13000).
[*] dyld load address check at 0x10da46000
[*] Arch-64
[*] dyld load address check at 0x11c2d6000
[*] Arch-64
[+] DyldImageLoadAddress: 0x11c2d6000
>>
```

#### Make

#### Usage

#### Update Log

```
# 2017.03.29 haha... it can dump class and method, but just demo, need perfect.
--------------------------------------------------------------
RTspy - macOS/IOS (1.0.0) - by jmpews@gmail.com
--------------------------------------------------------------
>> attach 2754
[*] macho load at 0x100000000
[*] start dump macho...
[*] dump bin arch-64
[*] dumping class 'MyObject'
[*]     method name 'printt:'
```
