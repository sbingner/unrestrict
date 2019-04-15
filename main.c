#include <sys/param.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <mach/mach.h>
#include <mach/error.h>

#include "common.h"
#include "kern_utils.h"
#include "kexecute.h"
#include "kmem.h"
#include "offsetcache.h"
#include "osobject.h"
#include "offsetof.h"

bool initialized = false;
uint64_t offset_options = 0;

__attribute__((constructor))
void ctor() {
    bool found_offsets = false;
    kern_return_t err;

    DEBUGLOG("the fun and games shall begin! (applying lube...)");

    // tfp0, kexecute
    err = host_get_special_port(mach_host_self(), HOST_LOCAL_NODE, 4, &tfp0);
    if (err != KERN_SUCCESS) {
        DEBUGLOG("host_get_special_port 4: %s", mach_error_string(err));
        tfp0 = KERN_INVALID_TASK;
        return;
    }
    DEBUGLOG("tfp0: %x", tfp0);

    struct task_dyld_info dyld_info = { 0 };
    mach_msg_type_number_t count = TASK_DYLD_INFO_COUNT;
    if (task_info(tfp0, TASK_DYLD_INFO, (task_info_t)&dyld_info, &count) == 0 &&
            dyld_info.all_image_info_addr != 0 &&
            dyld_info.all_image_info_addr != dyld_info.all_image_info_size + 0xfffffff007004000) {
        kernel_slide = dyld_info.all_image_info_size;
        size_t blob_size = rk64(dyld_info.all_image_info_addr);
        DEBUGLOG("Restoring persisted offsets cache length %zu from 0x%llx", blob_size, dyld_info.all_image_info_addr);
        struct cache_blob *blob = create_cache_blob(blob_size);
        if (kread(dyld_info.all_image_info_addr, blob, blob_size)) import_cache_blob(blob);
        free(blob);
        if (get_offset("kernel_slide") == kernel_slide) {
            found_offsets = true;
            if (get_offset("kernel_base")) {
                kernel_base = get_offset("kernel_base");
            } else {
                DEBUGLOG("Didn't get kernel_base from cache???");
                kernel_base = dyld_info.all_image_info_size + 0xfffffff007004000;
            }

            offset_kernel_task = get_offset("kernel_task");
            offset_zonemap = get_offset("zone_map_ref");

            offset_add_ret_gadget = get_offset("add_x0_x0_0x40_ret");
            offset_osboolean_true = rk64(get_offset("OSBoolean_True"));
            offset_osboolean_false = rk64(get_offset("OSBoolean_True") + sizeof(void *));
            offset_osunserializexml = get_offset("osunserializexml");
            offset_smalloc = get_offset("smalloc");
            offset_options = get_offset("unrestrict-options");
            offset_paciza_pointer__l2tp_domain_module_start = get_offset("paciza_pointer__l2tp_domain_module_start");
            offset_paciza_pointer__l2tp_domain_module_stop = get_offset("paciza_pointer__l2tp_domain_module_stop");
            offset_l2tp_domain_inited = get_offset("l2tp_domain_inited");
            offset_sysctl__net_ppp_l2tp = get_offset("sysctl__net_ppp_l2tp");
            offset_sysctl_unregister_oid = get_offset("sysctl_unregister_oid");
            offset_mov_x0_x4__br_x5 = get_offset("mov_x0_x4__br_x5");
            offset_mov_x9_x0__br_x1 = get_offset("mov_x9_x0__br_x1");
            offset_mov_x10_x3__br_x6 = get_offset("mov_x10_x3__br_x6");
            offset_kernel_forge_pacia_gadget = get_offset("kernel_forge_pacia_gadget");
            offset_kernel_forge_pacda_gadget = get_offset("kernel_forge_pacda_gadget");
            offset_IOUserClient__vtable = get_offset("IOUserClient__vtable");
            offset_IORegistryEntry__getRegistryEntryID = get_offset("IORegistryEntry__getRegistryEntryID");
            DEBUGLOG("options: 0x%llx, OPT_GET_TASK_ALLOW:%d OPT_CS_DEBUGGED:%d", offset_options, OPT(GET_TASK_ALLOW), OPT(CS_DEBUGGED));
        }
    }

    if (!found_offsets) {
        CFURLRef fileURL = CFURLCreateWithFileSystemPath(kCFAllocatorDefault, CFSTR("/jb/offsets.plist"), kCFURLPOSIXPathStyle, false);
        if (fileURL == NULL) {
            DEBUGLOG("Unable to create URL");
            return;
        }
        CFDataRef off_file_data;
        SInt32 errorCode;
        Boolean status = CFURLCreateDataAndPropertiesFromResource(
                kCFAllocatorDefault, fileURL, &off_file_data,
                NULL, NULL, &errorCode);

        CFRelease(fileURL);
        if (!status) {
            DEBUGLOG("Unable to read /jb/offsets.plist");
            return;
        }

        DEBUGLOG("off_file_data: %p", off_file_data);
        CFPropertyListRef offsets = CFPropertyListCreateWithData(kCFAllocatorDefault, (CFDataRef)off_file_data, kCFPropertyListImmutable, NULL, NULL);
        CFRelease(off_file_data);
        if (offsets == NULL) {
            DEBUGLOG("Unable to convert /jb/offsets.plist to property list");
            return;
        }

        if (CFGetTypeID(offsets) != CFDictionaryGetTypeID()) {
            DEBUGLOG("/jb/offsets.plist did not convert to a dictionary");
            CFRelease(offsets);
            return;
        }

        // TODO: CFStringGetCStringPtr is not to be relied upon like this... bad things will happen if this is not fixed
        kernel_base                                     = strtoull(CFStringGetCStringPtr(CFDictionaryGetValue(offsets, CFSTR("KernelBase")), kCFStringEncodingUTF8), NULL, 16);
        kernel_slide                                    = strtoull(CFStringGetCStringPtr(CFDictionaryGetValue(offsets, CFSTR("KernelSlide")), kCFStringEncodingUTF8), NULL, 16);

        offset_kernel_task                              = strtoull(CFStringGetCStringPtr(CFDictionaryGetValue(offsets, CFSTR("KernelTask")), kCFStringEncodingUTF8), NULL, 16);
        offset_zonemap                                  = strtoull(CFStringGetCStringPtr(CFDictionaryGetValue(offsets, CFSTR("ZoneMapOffset")), kCFStringEncodingUTF8), NULL, 16);

        offset_add_ret_gadget                           = strtoull(CFStringGetCStringPtr(CFDictionaryGetValue(offsets, CFSTR("AddRetGadget")), kCFStringEncodingUTF8), NULL, 16);
        offset_osboolean_true                           = strtoull(CFStringGetCStringPtr(CFDictionaryGetValue(offsets, CFSTR("OSBooleanTrue")), kCFStringEncodingUTF8), NULL, 16);
        offset_osboolean_false                          = strtoull(CFStringGetCStringPtr(CFDictionaryGetValue(offsets, CFSTR("OSBooleanFalse")), kCFStringEncodingUTF8), NULL, 16);
        offset_osunserializexml                         = strtoull(CFStringGetCStringPtr(CFDictionaryGetValue(offsets, CFSTR("OSUnserializeXML")), kCFStringEncodingUTF8), NULL, 16);
        offset_smalloc                                  = strtoull(CFStringGetCStringPtr(CFDictionaryGetValue(offsets, CFSTR("Smalloc")), kCFStringEncodingUTF8), NULL, 16);
        offset_paciza_pointer__l2tp_domain_module_start = strtoull(CFStringGetCStringPtr(CFDictionaryGetValue(offsets, CFSTR("PacizaPointerL2TPDomainModuleStart")), kCFStringEncodingUTF8), NULL, 16);
        offset_paciza_pointer__l2tp_domain_module_stop  = strtoull(CFStringGetCStringPtr(CFDictionaryGetValue(offsets, CFSTR("PacizaPointerL2TPDomainModuleStop")), kCFStringEncodingUTF8), NULL, 16);
        offset_l2tp_domain_inited                       = strtoull(CFStringGetCStringPtr(CFDictionaryGetValue(offsets, CFSTR("L2TPDomainInited")), kCFStringEncodingUTF8), NULL, 16);
        offset_sysctl__net_ppp_l2tp                     = strtoull(CFStringGetCStringPtr(CFDictionaryGetValue(offsets, CFSTR("SysctlNetPPPL2TP")), kCFStringEncodingUTF8), NULL, 16);
        offset_sysctl_unregister_oid                    = strtoull(CFStringGetCStringPtr(CFDictionaryGetValue(offsets, CFSTR("SysctlUnregisterOid")), kCFStringEncodingUTF8), NULL, 16);
        offset_mov_x0_x4__br_x5                         = strtoull(CFStringGetCStringPtr(CFDictionaryGetValue(offsets, CFSTR("MovX0X4BrX5")), kCFStringEncodingUTF8), NULL, 16);
        offset_mov_x9_x0__br_x1                         = strtoull(CFStringGetCStringPtr(CFDictionaryGetValue(offsets, CFSTR("MovX9X0BrX1")), kCFStringEncodingUTF8), NULL, 16);
        offset_mov_x10_x3__br_x6                        = strtoull(CFStringGetCStringPtr(CFDictionaryGetValue(offsets, CFSTR("MovX10X3BrX6")), kCFStringEncodingUTF8), NULL, 16);
        offset_kernel_forge_pacia_gadget                = strtoull(CFStringGetCStringPtr(CFDictionaryGetValue(offsets, CFSTR("KernelForgePaciaGadget")), kCFStringEncodingUTF8), NULL, 16);
        offset_kernel_forge_pacda_gadget                = strtoull(CFStringGetCStringPtr(CFDictionaryGetValue(offsets, CFSTR("KernelForgePacdaGadget")), kCFStringEncodingUTF8), NULL, 16);
        offset_IOUserClient__vtable                     = strtoull(CFStringGetCStringPtr(CFDictionaryGetValue(offsets, CFSTR("IOUserClientVtable")), kCFStringEncodingUTF8), NULL, 16);
        offset_IORegistryEntry__getRegistryEntryID      = strtoull(CFStringGetCStringPtr(CFDictionaryGetValue(offsets, CFSTR("IORegistryEntryGetRegistryEntryID")), kCFStringEncodingUTF8), NULL, 16);
        
        CFRelease(offsets);
        found_offsets = true;
    }

    DEBUGLOG("kern base: %llx, slide: %llx", kernel_base, kernel_slide);
    DEBUGLOG("offset_kernel_task: %llx", offset_kernel_task);
    DEBUGLOG("offset_zonemap: %llx", offset_zonemap);
    DEBUGLOG("offset_add_ret_gadget: %llx", offset_add_ret_gadget);
    DEBUGLOG("offset_osboolean_true: %llx", offset_osboolean_true);
    DEBUGLOG("offset_osboolean_false: %llx", offset_osboolean_false);
    DEBUGLOG("offset_osunserializexml: %llx", offset_osunserializexml);
    DEBUGLOG("offset_smalloc: %llx", offset_smalloc);
    DEBUGLOG("offset_paciza_pointer__l2tp_domain_module_start: %llx", offset_paciza_pointer__l2tp_domain_module_start);
    DEBUGLOG("offset_paciza_pointer__l2tp_domain_module_stop: %llx", offset_paciza_pointer__l2tp_domain_module_stop);
    DEBUGLOG("offset_l2tp_domain_inited: %llx", offset_l2tp_domain_inited);
    DEBUGLOG("offset_sysctl__net_ppp_l2tp: %llx", offset_sysctl__net_ppp_l2tp);
    DEBUGLOG("offset_sysctl_unregister_oid: %llx", offset_sysctl_unregister_oid);
    DEBUGLOG("offset_mov_x0_x4__br_x5: %llx", offset_mov_x0_x4__br_x5);
    DEBUGLOG("offset_mov_x9_x0__br_x1: %llx", offset_mov_x9_x0__br_x1);
    DEBUGLOG("offset_mov_x10_x3__br_x6: %llx", offset_mov_x10_x3__br_x6);
    DEBUGLOG("offset_kernel_forge_pacia_gadget: %llx", offset_kernel_forge_pacia_gadget);
    DEBUGLOG("offset_kernel_forge_pacda_gadget: %llx", offset_kernel_forge_pacda_gadget);
    DEBUGLOG("offset_IOUserClient__vtable: %llx", offset_IOUserClient__vtable);
    DEBUGLOG("offset_IORegistryEntry__getRegistryEntryID: %llx", offset_IORegistryEntry__getRegistryEntryID);
    

    #define MEMORYSTATUS_CMD_SET_JETSAM_TASK_LIMIT 6
    extern int memorystatus_control(uint32_t command, int32_t pid, uint32_t flags, void *buffer, size_t buffersize);
    
    if (found_offsets && init_kexecute() && OSDictionary_SetItem(rk64(rk64(rk64(proc_find(getpid()) + offsetof_p_ucred) + 0x78) + 0x8), "com.apple.private.memorystatus", offset_osboolean_true) && memorystatus_control(MEMORYSTATUS_CMD_SET_JETSAM_TASK_LIMIT, getpid(), 0, NULL, 0) == 0) {
        DEBUGLOG("Initialized successfully!");
        initialized = true;
    } else {
        DEBUGLOG("Failed to initialize kexecute :(");
    }
}

__attribute__((destructor))
void dtor() {
    DEBUGLOG("Terminating kexecute");
    kern_utils_cleanup();
    term_kexecute();
}
