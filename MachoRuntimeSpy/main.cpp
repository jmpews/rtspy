#include <iostream>
#include "cli.hpp"
#include "Macho.hpp"
#include <unistd.h>


using namespace macho;

//machort::MachoRT target;

int main(int argc, const char * argv[]) {
    print_welcome();
    pid_t  targetPid;
    if(argc == 1) {
        targetPid = getpid();
    } else if(argc == 2) {
        targetPid = atoi(argv[1]);
    }


    std::cout << "[*] target pid: " << targetPid << std::endl;

    MachoRT target;
    target.setPid(targetPid);
    target.parse_macho();


    MachoFD dyld;
    dyld.setPath(target.m_dyld_path);
    dyld.parse_macho();
    if(target.searchDyldImageLoadAddress(dyld.m_vm_64_addr)) {
        std::cout << "[+] DyldImageLoadAddress: 0x" << std::hex << target.m_dyld_load_addr << std::endl;
    }
    return 0;
}

