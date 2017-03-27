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
