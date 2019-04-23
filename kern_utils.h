#import <stdio.h>

#import <mach/mach.h>
#import <mach/error.h>
#import <mach/message.h>

#import <CoreFoundation/CoreFoundation.h>

#include <pthread.h>

#include "cs_blobs.h"

/****** IOKit/IOKitLib.h *****/
typedef mach_port_t io_service_t;
typedef mach_port_t io_connect_t;

extern const mach_port_t kIOMasterPortDefault;
#define IO_OBJECT_NULL (0)

kern_return_t
IOConnectCallAsyncMethod(
                         mach_port_t     connection,
                         uint32_t        selector,
                         mach_port_t     wakePort,
                         uint64_t*       reference,
                         uint32_t        referenceCnt,
                         const uint64_t* input,
                         uint32_t        inputCnt,
                         const void*     inputStruct,
                         size_t          inputStructCnt,
                         uint64_t*       output,
                         uint32_t*       outputCnt,
                         void*           outputStruct,
                         size_t*         outputStructCntP);

kern_return_t
IOConnectCallMethod(
                    mach_port_t     connection,
                    uint32_t        selector,
                    const uint64_t* input,
                    uint32_t        inputCnt,
                    const void*     inputStruct,
                    size_t          inputStructCnt,
                    uint64_t*       output,
                    uint32_t*       outputCnt,
                    void*           outputStruct,
                    size_t*         outputStructCntP);

io_service_t
IOServiceGetMatchingService(
                            mach_port_t  _masterPort,
                            CFDictionaryRef  matching);

CFMutableDictionaryRef
IOServiceMatching(
                  const char* name);

kern_return_t
IOServiceOpen(
              io_service_t  service,
              task_port_t   owningTask,
              uint32_t      type,
              io_connect_t* connect );

kern_return_t IOConnectTrap6(io_connect_t connect, uint32_t index, uintptr_t p1, uintptr_t p2, uintptr_t p3, uintptr_t p4, uintptr_t p5, uintptr_t p6);
kern_return_t mach_vm_read(vm_map_t target_task, mach_vm_address_t address, mach_vm_size_t size, vm_offset_t *data, mach_msg_type_number_t *dataCnt);
kern_return_t mach_vm_read_overwrite(vm_map_t target_task, mach_vm_address_t address, mach_vm_size_t size, mach_vm_address_t data, mach_vm_size_t *outsize);
kern_return_t mach_vm_write(vm_map_t target_task, mach_vm_address_t address, vm_offset_t data, mach_msg_type_number_t dataCnt);
kern_return_t mach_vm_allocate(vm_map_t target, mach_vm_address_t *address, mach_vm_size_t size, int flags);
kern_return_t mach_vm_deallocate(vm_map_t target, mach_vm_address_t address, mach_vm_size_t size);

#define PROC_PIDPATHINFO_MAXSIZE  (4 * MAXPATHLEN)
int proc_pidpath(pid_t pid, void *buffer, uint32_t buffersize);

#define TF_PLATFORM 0x400
#define VSHARED_DYLD 0x000200

struct process_fixup {
    pid_t process_pid;
    const char *process_path;
};

enum {
    FIXUP_CS_FLAGS = 1,
    FIXUP_T_FLAGS = 2,
    FIXUP_SETUID = 3,
    FIXUP_SANDBOX = 4,
    FIXUP_AMFI_ENTITLEMENTS = 5,
};

extern mach_port_t tfp0;
extern uint64_t kernel_base;
extern uint64_t kernel_slide;

extern uint64_t offset_kernel_task;
extern uint64_t offset_zonemap;
extern uint64_t offset_add_ret_gadget;
extern uint64_t offset_osboolean_true;
extern uint64_t offset_osboolean_false;
extern uint64_t offset_osunserializexml;
extern uint64_t offset_smalloc;
extern uint64_t offset_paciza_pointer__l2tp_domain_module_start;
extern uint64_t offset_paciza_pointer__l2tp_domain_module_stop;
extern uint64_t offset_l2tp_domain_inited;
extern uint64_t offset_sysctl__net_ppp_l2tp;
extern uint64_t offset_sysctl_unregister_oid;
extern uint64_t offset_mov_x0_x4__br_x5;
extern uint64_t offset_mov_x9_x0__br_x1;
extern uint64_t offset_mov_x10_x3__br_x6;
extern uint64_t offset_kernel_forge_pacia_gadget;
extern uint64_t offset_kernel_forge_pacda_gadget;
extern uint64_t offset_IOUserClient__vtable;
extern uint64_t offset_IORegistryEntry__getRegistryEntryID;
extern uint64_t offset_vfs_context_current;
extern uint64_t offset_vnode_lookup;
extern uint64_t offset_vnode_put;
extern uint64_t offset_proc_find;
extern uint64_t offset_proc_rele;

extern pthread_mutex_t fixup_lock;

uint64_t find_port(mach_port_name_t port);

uint64_t proc_find(pid_t pid);
uint64_t our_task_addr(void);
void kern_utils_cleanup(void);

void fixup_mmap(const char *path);
void fixup_process(const struct process_fixup *fixup, int options);
