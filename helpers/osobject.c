#include <stdlib.h>

#include "kern_utils.h"
#include "kexecute.h"
#include "kmem.h"
#include "osobject.h"
#include "common.h"
#include "pac.h"
#include "kernel_call.h"

// offsets in vtable:
static uint32_t off_OSDictionary_SetObjectWithCharP = sizeof(void*) * 0x1F;
static uint32_t off_OSDictionary_GetObjectWithCharP = sizeof(void*) * 0x26;
static uint32_t off_OSDictionary_Merge              = sizeof(void*) * 0x23;

static uint32_t off_OSArray_Merge                   = sizeof(void*) * 0x1E;
static uint32_t off_OSArray_RemoveObject            = sizeof(void*) * 0x20;
static uint32_t off_OSArray_GetObject               = sizeof(void*) * 0x22;

static uint32_t off_OSObject_Release                = sizeof(void*) * 0x05;
static uint32_t off_OSObject_GetRetainCount         = sizeof(void*) * 0x03;
static uint32_t off_OSObject_Retain                 = sizeof(void*) * 0x04;

static uint32_t off_OSString_GetLength              = sizeof(void*) * 0x11;

static inline uint64_t OSObjectFunc(uint64_t osobject, uint32_t off) {
    uint64_t OSObjectFunc = 0;
    uint64_t vtable = rk64(osobject);
    vtable = kernel_xpacd(vtable);
    if (vtable != 0) {
        OSObjectFunc = rk64(vtable + off);
        OSObjectFunc = kernel_xpaci(OSObjectFunc);
    }
    return OSObjectFunc;
}

bool OSDictionary_SetItem(uint64_t dict, const char *key, uint64_t val) {
    uint64_t function = OSObjectFunc(dict, off_OSDictionary_SetObjectWithCharP);
    uint64_t ks = kstralloc(key);
    bool rv = (bool)kexecute(function, dict, ks, val, 0, 0, 0, 0);
    kstrfree(ks);
    return rv;
}

// XXX it can return 0 in lower 32 bits but still be valid
// fix addr of returned value and check if rk64 gives ptr
// to vtable addr saved before

// address if exists, 0 if not
uint64_t _OSDictionary_GetItem(uint64_t dict, const char *key) {
    uint64_t function = OSObjectFunc(dict, off_OSDictionary_GetObjectWithCharP);
    uint64_t ks = kstralloc(key);
    uint64_t rv = kexecute(function, dict, ks, 0, 0, 0, 0, 0);
    kstrfree(ks);
    return rv;
}

uint64_t OSDictionary_GetItem(uint64_t dict, const char *key) {
    uint64_t ret = _OSDictionary_GetItem(dict, key);
    
    if (ret != 0 && (ret>>32) == 0) {
        // XXX can it be not in zalloc?..
        ret = zm_fix_addr(ret);
    }

    return ret;
}

bool OSDictionary_Merge(uint64_t dict, uint64_t aDict) {
    uint64_t function = OSObjectFunc(dict, off_OSDictionary_Merge);
    return (int)kexecute(function, dict, aDict, 0, 0, 0, 0, 0);
}

bool OSArray_Merge(uint64_t array, uint64_t aArray) {
    uint64_t function = OSObjectFunc(array, off_OSArray_Merge);
    return (int)kexecute(function, array, aArray, 0, 0, 0, 0, 0);
}

uint64_t _OSArray_GetObject(uint64_t array, unsigned int idx){
    uint64_t function = OSObjectFunc(array, off_OSArray_GetObject);
    return kexecute(function, array, idx, 0, 0, 0, 0, 0);
}

uint64_t OSArray_GetObject(uint64_t array, unsigned int idx){
    uint64_t ret = _OSArray_GetObject(array, idx);
    
    if (ret != 0){
        // XXX can it be not in zalloc?..
        ret = zm_fix_addr(ret);
    }
    return ret;
}

void OSArray_RemoveObject(uint64_t array, unsigned int idx){
    uint64_t function = OSObjectFunc(array, off_OSArray_RemoveObject);
    (void)kexecute(function, array, idx, 0, 0, 0, 0, 0);
}

// XXX error handling just for fun? :)
uint64_t _OSUnserializeXML(const char *buffer) {
    uint64_t ks = kstralloc(buffer);
    uint64_t errorptr = 0;
    uint64_t rv = kexecute(offset_osunserializexml, ks, errorptr, 0, 0, 0, 0, 0);
    kstrfree(ks);
    return rv;
}

uint64_t OSUnserializeXML(const char *buffer) {
    uint64_t ret = _OSUnserializeXML(buffer);
    
    if (ret != 0) {
        // XXX can it be not in zalloc?..
        ret = zm_fix_addr(ret);
    }

    return ret;
}

void OSObject_Release(uint64_t osobject) {
    uint64_t function = OSObjectFunc(osobject, off_OSObject_Release);
    (void)kexecute(function, osobject, 0, 0, 0, 0, 0, 0);
}

void OSObject_Retain(uint64_t osobject) {
    uint64_t function = OSObjectFunc(osobject, off_OSObject_Retain);
    (void)kexecute(function, osobject, 0, 0, 0, 0, 0, 0);
}

uint32_t OSObject_GetRetainCount(uint64_t osobject) {
    uint64_t function = OSObjectFunc(osobject, off_OSObject_GetRetainCount);
    return (uint32_t)kexecute(function, osobject, 0, 0, 0, 0, 0, 0);
}

unsigned int OSString_GetLength(uint64_t osstring){
    uint64_t function = OSObjectFunc(osstring, off_OSString_GetLength);
    return (unsigned int)kexecute(function, osstring, 0, 0, 0, 0, 0, 0);
}

char *OSString_CopyString(uint64_t osstring){
    unsigned int length = OSString_GetLength(osstring);
    if (length == 0 || length > 0x100) DEBUGLOG("OSString_CopyString: length=%d", length);
    char *str = (char *)malloc(length + 1);
    if (!str) {
        DEBUGLOG("malloc failed OSString_CopyString: str=%p", str);
    }
    str[length] = 0;
    
    kread(OSString_CStringPtr(osstring), str, length);
    return str;
}
