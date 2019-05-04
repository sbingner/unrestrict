#ifndef kern_utils_h
#define kern_utils_h

#import <CoreFoundation/CoreFoundation.h>
#import <mach/mach.h>
#include <pthread.h>
#include <cs_blobs.h>
#include <iokit.h>

#define SIZEOF_STRUCT_EXTENSION 0x60

#define TF_PLATFORM 0x00000400 /* task is a platform binary */

#define PROC_PIDPATHINFO_MAXSIZE  (4 * MAXPATHLEN)
int proc_pidpath(pid_t pid, void *buffer, uint32_t buffersize);

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
extern uint64_t offset_sstrdup;
extern uint64_t offset_extension_create_file;
extern uint64_t offset_extension_add;
extern uint64_t offset_extension_release;
extern uint64_t offset_strlen;
extern uint64_t offset_sfree;

extern pthread_mutex_t fixup_lock;

uint64_t proc_find(pid_t pid);
void proc_rele(uint64_t proc);
uint64_t our_task_addr(void);
uint64_t find_port(mach_port_name_t port);
uint64_t get_exception_osarray(const char **exceptions);
void release_exception_osarray(uint64_t *exception_osarray);
void set_sandbox_extensions(uint64_t proc, uint64_t proc_ucred, uint64_t sandbox);
char **copy_amfi_entitlements(uint64_t present);
void set_amfi_entitlements(uint64_t proc, uint64_t proc_ucred, uint64_t amfi_entitlements, uint64_t sandbox);
size_t kstrlen(uint64_t ptr);
uint64_t kstralloc(const char *str);
void kstrfree(uint64_t ptr);

void fixup_cs_flags(uint64_t proc);
void fixup_t_flags(uint64_t proc);
void fixup_setuid(pid_t pid, uint64_t proc, uint64_t ucred, const char *path);
void fixup_sandbox(uint64_t proc, uint64_t proc_ucred, uint64_t sandbox);
void fixup_amfi_entitlements(uint64_t proc, uint64_t proc_ucred, uint64_t amfi_entitlements, uint64_t sandbox);

void fixup_process(const struct process_fixup *fixup, int options);

void kern_utils_cleanup(void);

#endif
