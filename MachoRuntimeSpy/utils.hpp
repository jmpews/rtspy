#ifndef utils_hpp
#define utils_hpp

#include <stdio.h>
#include <stdlib.h>
#include <err.h>

#include <mach/task_info.h>
#include <mach/task.h>
#include <mach-o/dyld_images.h>

//#ifdef __arm64__
//#else
//#include <mach/mach_vm.h>
//#endif

task_t pid2task(unsigned int pid);

bool readTaskMemory (task_t t, vm_address_t addr, void* buf, unsigned long len);
char* readTaskString(task_t t, vm_address_t addr);
vm_address_t getDyldLoadAddress(task_t task);

vm_address_t memorySearch(task_t task, vm_address_t start, vm_address_t end, char *data, unsigned long len);
vm_address_t memorySearchDyld(task_t task, vm_address_t start,char *data, unsigned long size);

#endif
