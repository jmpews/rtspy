#include "utils.hpp"
#include "cli.hpp"
#include <mach-o/dyld_images.h>

bool readTaskMemory(task_t t, vm_address_t addr, void *buf, unsigned long len)
{
    if(addr <= 0)
        Serror("memory read address < 0");
    if(len <= 0)
        Serror("memory read length <0");

    vm_size_t dataCnt = len;
    kern_return_t kr = vm_read_overwrite(t, addr, len, (vm_address_t)buf, (vm_size_t *)&dataCnt);

    if (kr)
        return false;
    if (len != dataCnt)
    {
        warnx("rt_read size return not match!");
        return false;
    }

    return true;
}

char *readTaskString(task_t t, vm_address_t addr)
{
    char x = '\0';
    vm_address_t end;
    char *str = NULL;

    //string upper limit 0x1000
    end = memorySearch(t, addr, addr + 0x1000, &x, 1);
    if (!end)
    {
        return NULL;
    }
    str = (char *)malloc(end - addr + 1);
    if (readTaskMemory(t, addr, str, end - addr + 1)) {
        return str;
    }

    return NULL;
}

task_t pid2task(unsigned int pid)
{
    task_t t;
    kern_return_t ret = task_for_pid(mach_task_self(), pid, &t);
    if (ret != KERN_SUCCESS) {
        printf("Attach to: %d Failed: %d %s\n", pid, ret, mach_error_string(ret));
        return 0;
    }
    return t;
}

//get dyld load address by task_info, TASK_DYLD_INFO
vm_address_t getDyldLoadAddress(task_t task) {
    //http://stackoverflow.com/questions/4309117/determining-programmatically-what-modules-are-loaded-in-another-process-os-x
    kern_return_t kr;
    task_flavor_t flavor = TASK_DYLD_INFO;
    task_dyld_info_data_t infoData;
    mach_msg_type_number_t task_info_outCnt = TASK_DYLD_INFO_COUNT;
    kr = task_info(task,
                     flavor,
                     (task_info_t)&infoData,
                     &task_info_outCnt
                     );
    if(kr){
        Serror("getDyldLoadAddress:task_info error");
        return 0;
    }
    struct dyld_all_image_infos *allImageInfos = (struct dyld_all_image_infos *)infoData.all_image_info_addr;
    allImageInfos = (struct dyld_all_image_infos *)malloc(sizeof(struct dyld_all_image_infos));
    if(readTaskMemory(task, infoData.all_image_info_addr, allImageInfos, sizeof(struct dyld_all_image_infos))) {
        return (vm_address_t)(allImageInfos->dyldImageLoadAddress);
    } else {
        Serror("getDyldLoadAddress:readTaskMemory error");
        return 0;
    }
}

vm_address_t memorySearch(task_t task, vm_address_t start, vm_address_t end, char *data, unsigned long len)
{
    if(start <= 0)
        Serror("memory search address < 0");
    if(start > end)
        Serror("memeory search end < start");
    vm_address_t addr = start;
    char *buf = (char *)malloc(len);
    while (end > addr)
    {
        if (readTaskMemory(task, addr, buf, len))
            if (!memcmp(buf, data, len))
            {
                return addr;
            }
        addr += len;
    }
    return 0;

    //    unsigned long search_block_size = 0x1000;
    //    vm_address_t addr  = start;
    //
    //    char *buf = (char *)malloc(search_block_size + len);
    //    unsigned long search_len;
    //    search_len =  search_block_size;
    //
    //    while(end >= addr + len || (!end)) {
    //
    //        if(readTaskMemory(task, addr, buf, search_len + len - 1)) {
    //            if(len == 1) {
    //                std::cout << "memorySearch: " << buf << std::endl;
    //            }
    //            for(char *p = buf; p < buf + search_len; p++){
    //
    //                if(!memcmp(p, data, len)) {
    //                    return addr + p - buf;
    //                }
    //            }
    //        } else {
    //            if(len == 1) {
    //                sleep(-1);
    //                std::cout << "memorySearch: error" << std::endl;
    //            }
    //        }
    //
    //        addr += search_block_size;
    //    }
    //
    //    search_len = end - addr - (len - 1);
    //    if(search_len >0 && readTaskMemory(task, addr, buf, search_len + len - 1)) {
    //        for(char *p = buf; p < buf + search_len; p++){
    //            if(!memcmp(p, data, len)) {
    //                return addr + p - buf;
    //            }
    //        }
    //    }
    //    return 0;
}
