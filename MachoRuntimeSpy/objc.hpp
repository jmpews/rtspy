#ifndef objc_hpp
#define objc_hpp

#include <stdint.h>

namespace objc {
#define FAST_DATA_MASK 0x00007ffffffffff8UL
#define RW_REALIZED           (1<<31)
#define RW_REALIZING          (1<<19)

    typedef void protocol_list_t;
    typedef void ivar_list_t;
    typedef void property_list_t;

    struct method_t {
        void *name;
        const char *types;
        void *imp;
    };

    typedef struct {
        uint32_t entsizeAndFlags;
        uint32_t count;
        struct method_t first;
    } method_list_t;

#if __LP64__
    typedef uint32_t mask_t;  // x86_64 & arm64 asm are less efficient with 16-bits
#else
    typedef uint16_t mask_t;
#endif

/// An opaque type that represents an Objective-C class.
    typedef struct objc_class *Class;

/// Represents an instance of a class.
    struct objc_object {
        Class isa;
    };

    struct class_ro_t {
        uint32_t flags;
        uint32_t instanceStart;
        uint32_t instanceSize;
#ifdef __LP64__
        uint32_t reserved;
#endif

        const uint8_t *ivarLayout;

        const char *name;
        method_list_t *baseMethodList;
        protocol_list_t *baseProtocols;
        const ivar_list_t *ivars;

        const uint8_t *weakIvarLayout;
        property_list_t *baseProperties;
    };

    // important！！！ if write use C++, 'template' may be the better chooise.
    typedef void List;

    struct array_t {
        uint32_t count;
        List *lists[0];
    };

    typedef struct list_array_tt {
        union {
            List *list;
            uintptr_t arrayAndFlag;
        };
    } x_array_t;

    // list_array_tt method
    bool hasArray(x_array_t *t);

    array_t *array(x_array_t *t);

    List **arrayList(x_array_t *t);

    struct class_rw_t {
        // Be warned that Symbolication knows the layout of this structure.
        uint32_t flags;
        uint32_t version;

        const class_ro_t *ro;

        x_array_t methods;
        x_array_t properties;
        x_array_t protocols;

        Class firstSubclass;
        Class nextSiblingClass;

        char *demangledName;

#if SUPPORT_INDEXED_ISA
        uint32_t index;
#endif
    };

    struct objc_class {
        Class isa;         // metaclass
        Class superclass;  // superclas
        // struct bucket_t *
        void *_buckets;    // cache
        mask_t _mask;      // vtable
        mask_t _occupied;  // vtable
        uintptr_t bits;    // data
    };

    class_rw_t *get_objc_class_data_addr(uintptr_t bits);
}
#endif