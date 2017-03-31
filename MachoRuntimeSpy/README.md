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
# 2017.03.31 it can dump class's ivars, and add anthoer method to get DyldImageLoadAddress, task_info(TASK_DYLD_INFO)
--------------------------------------------------------------
RTspy - macOS/IOS (1.0.0) - by jmpews@gmail.com
--------------------------------------------------------------
>> attach 49444
[*] macho load at 0x100000000
[*] start dump macho...
[*] dump bin arch-64
[*] class has been realized
[*] dumping class 'MyObject', 0x100000f43
[*]     method name 'printt:'
[*]     method name 'printtt:'
[*]     ivar name 't'
[*] class not be realized
[*] dumping class 'XMyObject', 0x100000f4c
[*]     method name 'printt:'
[*]     method name 'printtt:'
[*]     ivar name 't'
[*] string table addr: 0x100002520
[*] symbol table addr: 0x100002520
[*] dyld path: /usr/lib/dyld.
[*] start dump macho...
[*] dump macho arch-fat
[*] start dump macho...
[*] dump macho arch-64
[*] __TEXT segment vm_addr: 0x0
[!] Macho.cpp:160:parse_universal(): only support x86_64.
[*] start dyld search range(0x100003000, 0x110003000).
[*] dyld load address check at 0x100036000
[*] dump bin arch-64
[*] dyld load address check at 0x108844000
[*] dump bin arch-64
[*] task_info() dyld_addr: 0x108844000
[+] DyldImageLoadAddress: 0x108844000
# 2017.03.31 it can dump class more perfet, now can tell whether A 'class' is used
--------------------------------------------------------------
RTspy - macOS/IOS (1.0.0) - by jmpews@gmail.com
--------------------------------------------------------------
>> attach 30650
[*] macho load at 0x100000000
[*] start dump macho...
[*] dump bin arch-64
[*] class has been realized
[*] dumping class 'MyObject', 0x100000f43
[*]     method name 'printt:'
[*]     method name 'printtt:'
[*] class not be realized
[*] dumping class 'XMyObject', 0x100000f4c
[*]     method name 'printt:'
[*]     method name 'printtt:'
[*] string table addr: 0x100002520
[*] symbol table addr: 0x100002520
[*] dyld path: /usr/lib/dyld.
[*] start dump macho...
[*] dump macho arch-fat
[*] start dump macho...
[*] dump macho arch-64
[*] __TEXT segment vm_addr: 0x0
[!] Macho.cpp:158:parse_universal(): only support x86_64.
[*] start dyld search range(0x100003000, 0x110003000).
[*] dyld load address check at 0x100036000
[*] dump bin arch-64
[*] dyld load address check at 0x1036bc000
[*] dump bin arch-64
[+] DyldImageLoadAddress: 0x1036bc000
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
