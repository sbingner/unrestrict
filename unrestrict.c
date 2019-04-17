#import <sys/param.h>
#import <mach/mach.h>
#import <sys/stat.h>
#import <os/log.h>
#import <dirent.h>
#import "kern_utils.h"
#import "common.h"

FILE *log_file = NULL;

bool MSunrestrict0(mach_port_t task) {
    if (!initialized) return true;

    char pathbuf[PROC_PIDPATHINFO_MAXSIZE];
    bzero(pathbuf, sizeof(pathbuf));

    pid_t pid;
    if ( (pid_for_task(task, &pid) != 0) || pid <= 1) {
        return true;
    }
    proc_pidpath(pid, pathbuf, sizeof(pathbuf));
    
    if (strcmp(pathbuf, "/usr/libexec/xpcproxy")==0 ||
        strcmp(pathbuf, "/usr/libexec/securityd")==0 ||
        strcmp(pathbuf, "/usr/libexec/trustd")==0) {
        return true;
    }
    
    const struct process_fixup fixup = {pid, pathbuf};
    int options = FIXUP_CS_FLAGS|FIXUP_T_FLAGS|FIXUP_SETUID|FIXUP_SANDBOX|FIXUP_AMFI_ENTITLEMENTS;
    fixup_process(&fixup, options);
    
    return true;
}

bool MSrevalidate0(mach_port_t task) {
    if (!initialized) return true;

    char pathbuf[PROC_PIDPATHINFO_MAXSIZE];
    bzero(pathbuf, sizeof(pathbuf));

    pid_t pid;
    if ( (pid_for_task(task, &pid) != 0) || pid <= 1) {
        return true;
    }
    proc_pidpath(pid, pathbuf, sizeof(pathbuf));

    if (strcmp(pathbuf, "/usr/libexec/xpcproxy")==0 ||
        strcmp(pathbuf, "/usr/libexec/securityd")==0 ||
        strcmp(pathbuf, "/usr/libexec/trustd")==0) {
        return true;
    }
    
    const struct process_fixup fixup = {pid, pathbuf};
    int options = FIXUP_CS_FLAGS;
    fixup_process(&fixup, options);

    return true;
}
