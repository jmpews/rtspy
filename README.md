## rtspy

runtime spy on elf and macho inlucde android/linux/ios/macOS.

**In development...**

## [ELFRuntimeSpy](http://github.com/jmpews/rtspy/blob/master/ELFRuntimeSpy)

## [MachoRuntimeSpy](http://github.com/jmpews/rtspy/blob/master/MachoRuntimeSpy)

#### Demo

```
jmpews at Jmp in ~/Desktop/rtspy/MachoRuntimeSpy (master●) (normal)
λ : sudo ./rtspy-mac
Password:
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
```
