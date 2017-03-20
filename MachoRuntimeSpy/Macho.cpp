#include "Macho.hpp"
#include "utils.hpp"
#include "cli.hpp"

namespace macho {
    MachoFD::MachoFD() {
        m_isRT = false;
    }

    bool MachoFD::setPath(char *path) {
        int fd;
        void *data;

        fd = open(path, O_RDONLY);
        if (fd < 0) {
            return false;
        }

        struct stat stbuf;
        if (fstat(fd, &stbuf) != 0) {
            return false;
        }

        /* mmap */
        data = mmap(NULL, stbuf.st_size, PROT_READ, MAP_FILE | MAP_PRIVATE, fd, 0);
        if (data == MAP_FAILED) {
            return false;
        }
        m_input.fd = fd;
        m_input.data = data;
        m_input.baseAddr = (unsigned long)data;
        m_input.length = stbuf.st_size;
        return true;
    }

    bool MachoFD::macho_read(unsigned long addr, void *data, unsigned long len) {
        if (addr - (unsigned long) m_input.data > m_input.length) {
            xerror("macho_read over.");
            return false;
        }
        memcpy(data, (void *) addr, len);
        return true;
    }

    char *MachoFD::macho_read_string(unsigned long addr) {
        char *xaddr = (char *) addr;
        unsigned int string_limit = 1024;
        unsigned int i;
        for (i = 0; i < string_limit; i++) {
            if (*(xaddr + i) == '\0')
                break;
        }
        if (i == string_limit)
            return NULL;
        else {
            char *result = (char *) malloc(i);
            memcpy(result, xaddr, i);
            return result;
        }

    }

    bool MachoFD::macho_off_read(unsigned long offset, void *data, unsigned long len) {
        unsigned long baseAddr = m_input.baseAddr;
        return macho_read(baseAddr + offset, data, len);
    }

    bool MachoFD::checkInitialization() {
        if (m_input.fd == 0) {
            xerror("MachoRT must be init.");
            return false;
        }
        return true;
    }

    bool MachoFD::parse_macho() {
        xinfo("start dump macho:");
        if (!parse_header())
            return false;
        if (m_isUniversal)
            parse_universal();
        else
            parse_load_commands();
        return false;
        return true;
    }

    bool MachoFD::parse_header() {

        /* Read the file type. */
        uint32_t magic;
        if (!macho_read(m_input.baseAddr, &magic, sizeof(uint32_t)))
            return false;

        switch (magic) {
            case MH_MAGIC_64:
                m_is64bit = true;
                m_header64 = (struct mach_header_64 *) malloc(sizeof(struct mach_header_64));
                if (!macho_read(m_input.baseAddr, m_header64, sizeof(struct mach_header_64)))
                    return false;
                xinfo("Arch-64");
                break;

            case FAT_CIGAM:
            case FAT_MAGIC:
                m_isUniversal = true;
                m_fat_header = (struct fat_header *) malloc(sizeof(struct fat_header));
                if (!macho_read(m_input.baseAddr, m_fat_header, sizeof(struct fat_header)))
                    return false;
                xinfo("Arch-fat");
                break;

            default:
                xerror("only support x86_64.");
                return false;
        }
        return true;
    }

    bool MachoFD::parse_universal() {
        unsigned long addr = m_input.baseAddr + sizeof(struct fat_header);
        uint32_t nfat = OSSwapBigToHostInt32(m_fat_header->nfat_arch);

        for (uint32_t i = 0; i < nfat; i++) {
            struct fat_arch *arch = (struct fat_arch *) malloc(sizeof(struct fat_arch));
            macho_read(addr, arch, sizeof(struct fat_arch));

            size_t length = OSSwapBigToHostInt32(arch->size);
            MachoFD *xmacho = new MachoFD();
            xmacho->m_input.data = (void *) ((unsigned long) m_input.data + OSSwapBigToHostInt32(arch->offset));
            xmacho->m_input.baseAddr = (unsigned long)xmacho->m_input.data;
            xmacho->m_input.fd = m_input.fd;
            xmacho->m_input.length = length;

            fat_arch_info_t fat_arch_info;
            fat_arch_info.arch = arch;
            fat_arch_info.macho = xmacho;

            m_fat_arch_infos.push_back(fat_arch_info);
        }

        std::vector<fat_arch_info_t>::iterator iter;
        fat_arch_info_t *xfat_arch_info;
        for (iter = m_fat_arch_infos.begin(); iter != m_fat_arch_infos.end(); iter++) {
            xfat_arch_info = &(*iter);
            switch (OSSwapBigToHostInt32(xfat_arch_info->arch->cputype)) {
                case CPU_TYPE_X86_64:
                    ((MachoFD *) (xfat_arch_info->macho))->parse_macho();
                    break;
                case CPU_TYPE_ARM64:
                    ((MachoFD *) (xfat_arch_info->macho))->parse_macho();
                    break;
                default:
                    xerror("only support x86_64.");
                    break;
            }
        }
        return true;
    }

    bool MachoFD::parse_load_command_headers() {
        uint32_t ncmds = 0;
        unsigned long addr = m_input.baseAddr;

        if (m_is64bit) {
            ncmds = m_header64->ncmds;
            addr += sizeof(mach_header_64); // load_command addr
        } else {
            xerror("only support x86_64.");
            return false;
        }

        struct load_command *cmd;

        for (int i = 0; i < ncmds; i++) {
            load_command_info_t load_cmd_info;
            cmd = (struct load_command *) malloc(sizeof(struct load_command));
            macho_read(addr, cmd, sizeof(struct load_command));
            load_cmd_info.cmd = cmd;

            switch (cmd->cmd) {
                case LC_SEGMENT_64:
                    struct segment_command_64 *seg_cmd_64;
                    seg_cmd_64 = (struct segment_command_64 *) malloc(sizeof(struct segment_command_64));
                    macho_read(addr, seg_cmd_64, sizeof(struct segment_command_64));
                    // important!
                    load_cmd_info.cmd_info = seg_cmd_64;
                    break;
                case LC_ID_DYLINKER:
                    m_isDyldLinker = true;
                    break;
                case LC_SYMTAB:
                    struct symtab_command *sym_cmd;
                    sym_cmd = (struct symtab_command *) malloc(sizeof(struct symtab_command));
                    macho_read(addr, sym_cmd, sizeof(struct symtab_command));
                    load_cmd_info.cmd_info = sym_cmd;
                    break;
                case LC_LOAD_DYLINKER:
                    struct dylinker_command *dy_cmd;
                    dy_cmd = (struct dylinker_command *) malloc(sizeof(struct dylinker_command));
                    macho_read(addr, sym_cmd, sizeof(struct symtab_command));
                    load_cmd_info.cmd_info = dy_cmd;
                    break;
                default:
                    load_cmd_info.cmd_info = NULL;
                    break;
            }

            load_cmd_info.cmd_addr = addr;
            /* add to vector STL */
            m_load_command_infos.push_back(load_cmd_info);

            /* move to next load_command */
            addr += cmd->cmdsize;
        }
        return true;
    }

    bool MachoFD::parse_load_commands() {
        parse_load_command_headers();
        /* iterate the load commands */
        std::vector<load_command_info_t>::iterator iter;
        load_command_info_t *load_cmd_info;
        for (iter = m_load_command_infos.begin(); iter != m_load_command_infos.end(); iter++) {
            load_cmd_info = &(*iter);
            switch (load_cmd_info->cmd->cmd) {
                case LC_SEGMENT_64:
                    if (!parse_LC_SEGMENT_64(load_cmd_info))
                        return false;
                    break;
                case LC_SYMTAB:
                    break;
                case LC_LOAD_DYLINKER:
                    break;
                default:
                    break;
            }

        }
        return true;
    }

    bool MachoFD::parse_LC_SEGMENT_64(load_command_info_t *load_cmd_info) {
        struct segment_command_64 *seg_cmd_64 = (struct segment_command_64 *) load_cmd_info->cmd_info;

        unsigned long addr = load_cmd_info->cmd_addr;;

        segment_command_64_info_t *seg_cmd_64_info = new segment_command_64_info_t();

        if (strcmp(seg_cmd_64->segname, "__TEXT") == 0) {
            m_vm_64_addr = seg_cmd_64->vmaddr;
            xdebug(printf("segment vm_addr: 0x%lx", m_vm_64_addr));
        }
        xdebug(printf("segment: %s's vmaddr_64: 0x%lx", seg_cmd_64->segname, seg_cmd_64->vmaddr));


        /* iterate dump section */
        struct section_64 *sect;
        addr += sizeof(struct segment_command_64);
        for (uint32_t nsect = 0; nsect < seg_cmd_64->nsects; nsect++) {
            sect = (struct section_64 *) malloc(sizeof(struct section_64));
            macho_read(addr, sect, sizeof(section_64));

            xdebug(printf("\tsection: %s's vmaddr: 0x%lx", sect->sectname, addr));

            seg_cmd_64_info->section_64_infos.push_back(sect);
            //TODO
            //section_64_infos.push_back(section);
            addr += sizeof(struct section_64);
        }

        m_segment_command_64_infos.push_back(seg_cmd_64_info);
        return true;
    }
}


namespace macho {
    MachoRT::MachoRT() {
        m_isRT = true;
        m_load_end_addr = 0L;
        m_load_addr = 0L;
        m_aslr_slide = 0L;
    }

    bool MachoRT::setPid(pid_t pid) {
        task_t t = pid2task(pid);
        if (t) {
            m_input.task = t;
            m_input.pid = pid;
            return true;
        }
        return false;
    }

    bool MachoRT::macho_read(unsigned long addr, void *data, unsigned long len) {
        task_t task = m_input.task;
        return readTaskMemory(task, (vm_address_t) addr, data, len);
    }

    char *MachoRT::macho_read_string(unsigned long addr) {
        task_t task = m_input.task;
        return readTaskString(task, (vm_address_t) addr);
    }

    bool MachoRT::macho_off_read(unsigned long offset, void *data, unsigned long len) {
        unsigned long baseAddr = m_input.baseAddr;
        task_t task = m_input.task;
        return readTaskMemory(task, (vm_address_t) (baseAddr + offset), data, len);
    }

    bool MachoRT::checkInitialization() {
        if (m_input.pid == 0) {
            xerror("MachoRT must be init.");
            return false;
        }
        return true;
    }

    bool MachoRT::searchBinLoadAddress() {
        //search align by memory page
        unsigned long search_block_size = 0x1000;
        unsigned long addr = MACHO_LOAD_ADDRESS;
        size_t aslr_limit = ((1 << 16) << 12) + 0x100000000;
        unsigned long end = addr + aslr_limit;
        char ch;

        while (end > addr) {
            if (macho_read(addr, &ch, 1)) {
                m_load_addr = addr;
                m_input.baseAddr = addr;
                xdebug(printf("macho load at 0x%lx", addr));
                return true;
            }
            addr += search_block_size;
        }
        xerror("searchBinLoadAddress failed.");
        return false;
    }

    bool MachoRT::parse_macho() {
        if (!checkInitialization())
            return false;
        if (!searchBinLoadAddress())
            return false;
        xinfo("start dump macho:");
        if (!parse_header())
            return false;
        parse_load_commands();
        return true;
    }

    bool MachoRT::parse_header() {

        uint32_t magic;
        if (!macho_read(m_load_addr, &magic, sizeof(magic)))
            return false;
        switch (magic) {
            case MH_MAGIC_64:
                m_is64bit = true;
                m_header64 = (struct mach_header_64 *) malloc(sizeof(struct mach_header_64));
                if (!macho_read(m_load_addr, m_header64, sizeof(struct mach_header_64)))
                    return false;
                xinfo("Arch-64");
                break;
            default:
                xerror("only support x86_64.");
                return false;
        }
        return true;
    }

    bool MachoRT::parse_load_command_headers() {
        uint32_t ncmds = 0;
        unsigned long addr = m_load_addr;

        if (m_is64bit) {
            ncmds = m_header64->ncmds;
            addr += sizeof(mach_header_64); // load_command addr
        } else {
            xerror("only support x86_64.");
            return false;
        }

        struct load_command *cmd;

        for (int i = 0; i < ncmds; i++) {
            load_command_info_t load_cmd_info;
            cmd = (struct load_command *) malloc(sizeof(struct load_command));
            macho_read(addr, cmd, sizeof(struct load_command));
            load_cmd_info.cmd = cmd;

            switch (cmd->cmd) {
                case LC_SEGMENT_64:
                    struct segment_command_64 *seg_cmd_64;
                    seg_cmd_64 = (struct segment_command_64 *) malloc(sizeof(struct segment_command_64));
                    macho_read(addr, seg_cmd_64, sizeof(struct segment_command_64));
                    load_cmd_info.cmd_info = seg_cmd_64;
                    break;
                case LC_ID_DYLINKER:
                    m_isDyldLinker = true;
                    break;
                case LC_SYMTAB:
                    struct symtab_command *sym_cmd;
                    sym_cmd = (struct symtab_command *) malloc(sizeof(struct symtab_command));
                    macho_read(addr, sym_cmd, sizeof(struct symtab_command));
                    load_cmd_info.cmd_info = sym_cmd;
                    break;
                case LC_LOAD_DYLINKER:
                    struct dylinker_command *dy_cmd;
                    dy_cmd = (struct dylinker_command *) malloc(sizeof(struct dylinker_command));
                    macho_read(addr, dy_cmd, sizeof(struct dylinker_command));
                    load_cmd_info.cmd_info = dy_cmd;
                    break;
                default:
                    load_cmd_info.cmd_info = NULL;
                    break;
            }
            load_cmd_info.cmd_addr = addr;
            /* add to vector STL */
            m_load_command_infos.push_back(load_cmd_info);

            /* move to next load_command */
            addr += cmd->cmdsize;
        }
        return true;
    }

    bool MachoRT::parse_load_commands() {
        parse_load_command_headers();
        /* iterate the load commands */
        std::vector<load_command_info_t>::iterator iter;
        load_command_info_t *load_cmd_info;
        for (iter = m_load_command_infos.begin(); iter != m_load_command_infos.end(); iter++) {
            load_cmd_info = &(*iter);
            switch (load_cmd_info->cmd->cmd) {
                case LC_SEGMENT_64:
                    if (!parse_LC_SEGMENT_64(load_cmd_info))
                        return false;
                    break;
                case LC_SYMTAB:
                    if (!parse_LC_SYMTAB(load_cmd_info))
                        return false;
                    break;
                case LC_LOAD_DYLINKER:
                    if (!parse_LC_LOAD_DYLINKER(load_cmd_info))
                        return false;
                    break;
                default:
                    break;
            }

        }
        return true;
    }

    bool MachoRT::parse_LC_LOAD_DYLINKER(load_command_info_t *load_cmd_info) {
        struct dylinker_command *dy_cmd = (struct dylinker_command *) load_cmd_info->cmd_info;
        m_dyld_path = macho_read_string(load_cmd_info->cmd_addr + dy_cmd->name.offset);
        xdebug(printf("dyld path: %s.", m_dyld_path));
        return true;
    }

    bool MachoRT::parse_LC_SYMTAB(load_command_info_t *load_cmd_info) {

        struct symtab_command *sym_cmd = (struct symtab_command *) load_cmd_info->cmd_info;
        m_symtab_addr = m_link_edit_bias + sym_cmd->symoff;
        m_strtab_addr = m_link_edit_bias + sym_cmd->stroff;

        xdebug(printf("string table addr: 0x%lx", m_strtab_addr));
        xdebug(printf("symbol table addr: 0x%lx", m_strtab_addr));

        struct nlist_64 *nl;
        nl = (struct nlist_64 *) malloc(sizeof(struct nlist_64));
        unsigned long addr = m_symtab_addr;
        for (int i = 0; i < sym_cmd->nsyms; i++) {
            macho_read(addr, nl, sizeof(struct nlist_64));
            if (nl->n_un.n_strx > 1) {
                char *sym_name = macho_read_string(m_strtab_addr + nl->n_un.n_strx);
                if (sym_name) {
                    if (!strcmp(sym_name, "_dlopen")) {
                        xdebug(printf("found function _dlopen: 0x%lx", m_load_addr + nl->n_value));
                    }
                    //                if(nl->n_type == N_FUN) {
                    //                    std::cout << "[+] function: " << sym_name << ", address: 0x" << std::hex << nl->n_value << std::endl;
                    //                }
                    //                if(nl->n_type & 0x1e) {
                    //                    std::cout << "[+] extern function: " << sym_name << ", address: 0x" << std::hex << nl->n_value << std::endl;
                    //                }
                    free(sym_name);
                } else {
                    // Generate an interrupt
                    xwarn("symbol read error");
                }
            }
            addr += sizeof(struct nlist_64);
        }

        return true;
    }

    bool MachoRT::parse_LC_SEGMENT_64(load_command_info_t *load_cmd_info) {
        struct segment_command_64 *seg_cmd_64 = (struct segment_command_64 *) load_cmd_info->cmd_info;

        unsigned long addr = load_cmd_info->cmd_addr;;

        segment_command_64_info_t *seg_cmd_64_info = new segment_command_64_info_t();

        if (strcmp(seg_cmd_64->segname, "__TEXT") == 0) {
            m_aslr_slide = m_load_addr - seg_cmd_64->vmaddr;
            // important!
            assert(m_load_addr == seg_cmd_64->vmaddr + m_aslr_slide);
        }

        /*
         set link edit bias
         how to calculate it?
         ref: dyld-421.2/src/ImageLoaderMachO.cpp
         ImageLoaderMachO::parseLoadCmds
         fLinkEditBase = (uint8_t*)(segActualLoadAddress(i) - segFileOffset(i));
         */

        if (strcmp(seg_cmd_64->segname, "__LINKEDIT") == 0) {
            //load_command_info_t* tmp;
            //tmp = getLoadCommand(LC_SEGMENT_64, "__TEXT");
            //vm_address_t text_vm_addr = ((struct segment_command_64*)tmp)->vmaddr;
            m_link_edit_bias = seg_cmd_64->vmaddr + m_aslr_slide - seg_cmd_64->fileoff;
        }

        // set load end addr
        if (seg_cmd_64->vmaddr + m_aslr_slide + seg_cmd_64->vmsize > m_load_end_addr) {
            m_load_end_addr = seg_cmd_64->vmaddr + m_aslr_slide + seg_cmd_64->vmsize;
        }

        xdebug(printf("segment: %s's vmaddr: 0x%lx", seg_cmd_64->segname, seg_cmd_64->vmaddr + m_aslr_slide));


        /* iterate dump section */
        struct section_64 *sect;
        addr += sizeof(struct segment_command_64);
        for (uint32_t nsect = 0; nsect < seg_cmd_64->nsects; nsect++) {
            sect = (struct section_64 *) malloc(sizeof(struct section_64));
            macho_read(addr, sect, sizeof(section_64));

            xdebug(printf("\tsection: %s's vmaddr: 0x%lx", sect->sectname, addr));

            seg_cmd_64_info->section_64_infos.push_back(sect);
            //TODO
            //section_64_infos.push_back(section);
            addr += sizeof(struct section_64);
        }

        m_segment_command_64_infos.push_back(seg_cmd_64_info);
        return true;
    }

    /* brute force search dyld*/
    bool MachoRT::searchDyldImageLoadAddress(unsigned long dyld_vm_addr) {
        unsigned long start_addr, addr, end_addr;
        uint64_t search_block_size = 0x1000;
        uint32_t magic_64 = MH_MAGIC_64;
        unsigned long aslr_limit = ((1 << 16) << 12);

        if (m_load_end_addr == 0)
            start_addr = MACHO_LOAD_ADDRESS;
        else
            start_addr = m_load_end_addr;

        if (dyld_vm_addr) {
            end_addr = dyld_vm_addr + aslr_limit;
            start_addr = dyld_vm_addr;
        } else {
            start_addr = start_addr;
            end_addr = (start_addr + aslr_limit) & (~(search_block_size - 1));
        }

        //search align by memory page

        // LINE: xnu-3789.41.3:mach_loader.c:383 dyld_aslr_offset
        // two condition!!!
        // LINE: xnu-3789.41.3:mach_loader.c:649
        // LINE: xnu-3789.41.3:mach_loader.c:718

        // slide = vm_map_round_page(slide + binresult->max_vm_addr, effective_page_mask);
        // LINE: xnu-3789.41.3:mach_loader.c:1364
        // vm_offset = scp->vmaddr + slide;

        char *buf = (char *) malloc(sizeof(uint32_t));

        addr = start_addr;

        xdebug(printf("start dyld search at 0x%lx", addr));

        while (end_addr > addr) {
            if (macho_read(addr, buf, sizeof(uint32_t))) {
                if ((!memcmp(buf, &magic_64, sizeof(uint32_t))) && check_dyld_arch(addr))
                    break;
            }

            addr += search_block_size;
        }

        if (addr < end_addr) {
            m_dyld_load_addr = addr;
            return true;
        } else {
            m_dyld_load_addr = 0;
            xerror("searchDyldImageLoadAddress failed.");
            return false;
        }
    }

    bool MachoRT::check_dyld_arch(unsigned long addr) {
        MachoRT dyld;
        dyld.m_load_addr = addr;
        dyld.m_input.pid = m_input.pid;
        dyld.m_input.task = m_input.task;
        dyld.m_input.baseAddr = addr;

        xdebug(printf("dyld load address check at 0x%lx", addr));
        if (!dyld.parse_header())
            return false;
        if (dyld.m_is64bit) {
            if (dyld.m_header64->filetype != MH_DYLINKER)
                return false;
            if (!dyld.parse_load_command_headers())
                return false;
            if (!dyld.m_isDyldLinker)
                return false;
        } else {
            return false;
        }

        return true;
    }
}
