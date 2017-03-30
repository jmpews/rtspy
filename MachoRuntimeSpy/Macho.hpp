#ifndef Macho_hpp
#define Macho_hpp

#include <iostream>
#include <stdio.h>
#include <vector>

#include <mach-o/fat.h>
#include <mach-o/loader.h>
#include <mach/mach_types.h>
#include <mach-o/nlist.h>

#include <assert.h>

#include <fcntl.h> //open
#include <sys/stat.h> //stat
#include <sys/mman.h> //mmap

#include "objc.hpp"

#define MACHO_LOAD_ADDRESS 0x100000000

namespace macho {
    typedef struct input_rt {
        pid_t pid;
        task_t task;
        unsigned long baseAddr;
    } input_rt_t;

    typedef struct input_fd {
        int fd;
        void *data;
        uint64_t length;
        unsigned long baseAddr;
    } input_fd_t;

    typedef struct load_command_info {
        struct load_command *cmd;
        void *cmd_info;
        unsigned long cmd_addr;
    } load_command_info_t;
    typedef std::vector<load_command_info_t> load_command_infos_t;

    typedef std::vector<struct section_64 *> section_64_infos_t;

    typedef struct segment_command_64_info {
        struct segment_command_64 *cmd;
        section_64_infos_t section_64_infos;
    } segment_command_64_info_t;
    typedef std::vector<segment_command_64_info_t *> segment_command_64_infos_t;

    typedef struct objc_class_info {
        unsigned long class_addr;
        struct objc::objc_class *objc;
        char *class_name;
    } objc_class_info_t;

    typedef std::vector<objc_class_info_t *> objc_class_infos_t;

    class Macho {
    public:
        bool m_isRT;
        bool m_is64bit;
        bool m_isDyldLinker;
        char *m_dyld_path;

        virtual bool parse_macho()=0;

        virtual bool parse_header()=0;

        virtual bool parse_load_commands()=0;

        virtual bool parse_load_command_headers()=0;

        virtual bool checkInitialization()=0;

        virtual bool macho_read(unsigned long addr, void *data, unsigned long len)=0;

        virtual bool macho_off_read(unsigned long offset, void *data, unsigned long len)=0;

        virtual char *macho_read_string(unsigned long addr)=0;

        struct mach_header *m_header;
        struct mach_header_64 *m_header64;
        load_command_infos_t m_load_command_infos;
        segment_command_64_infos_t m_segment_command_64_infos;
        objc_class_infos_t m_objc_class_infos;

    private:

    };

    typedef struct fat_arch_info {
        struct fat_arch *arch;
        Macho *macho;
    } fat_arch_info_t;

    typedef std::vector<fat_arch_info_t> fat_arch_infos_t;

    class MachoFD : public Macho {
    public:
        MachoFD();

        bool m_isUniversal;
        unsigned long m_vm_64_addr; //bin vm addr
        bool parse_universal();

        bool setPath(char *path);

        bool parse_macho();

        bool parse_header();

        bool parse_load_commands();

        bool parse_load_command_headers();

        bool parse_LC_SEGMENT_64(load_command_info_t *load_cmd_info);
        //bool parse_LC_SYMTAB(load_command_info_t *load_cmd_info);
        //bool parse_LC_LOAD_DYLINKER(load_command_info_t* load_cmd_info);


        bool checkInitialization();

        bool macho_read(unsigned long addr, void *data, unsigned long len);

        bool macho_off_read(unsigned long offset, void *data, unsigned long len);

        char *macho_read_string(unsigned long addr);

    private:
        input_fd_t m_input;
        struct fat_header *m_fat_header;
        fat_arch_infos_t m_fat_arch_infos;

    };

    class MachoRT : public Macho {
    public:
        MachoRT();

        unsigned long m_load_addr; //macho load vm addr
        unsigned long m_load_end_addr;
        size_t m_aslr_slide;
        unsigned long m_dyld_load_addr; //where is dyld load
        unsigned long m_symtab_addr;
        unsigned long m_strtab_addr;

        bool setPid(pid_t pid);

        bool searchBinLoadAddress();

        bool searchDyldImageLoadAddress(unsigned long dyld_vm_addr);

        bool check_dyld_arch(unsigned long addr);

        bool parse_macho();

        bool parse_header();

        bool parse_load_commands();

        bool parse_load_command_headers();

        bool parse_LC_SEGMENT_64(load_command_info_t *load_cmd_info);

        bool parse_LC_SYMTAB(load_command_info_t *load_cmd_info);

        bool parse_LC_LOAD_DYLINKER(load_command_info_t *load_cmd_info);

        bool parse_SECT_CLASSLIST(struct section_64 *sect);

        bool parse_CLASS(objc_class_info_t * objc_class_info);

        bool checkInitialization();

        bool macho_read(unsigned long addr, void *data, unsigned long len);

        bool macho_off_read(unsigned long offset, void *data, unsigned long len);

        char *macho_read_string(unsigned long addr);

    private:
        unsigned long m_link_edit_bias;
        input_rt_t m_input;
    };
}

static macho::MachoRT *mrt;
#endif
