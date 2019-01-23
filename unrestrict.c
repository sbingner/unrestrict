#import <sys/param.h>
#import <mach/mach.h>
#import <sys/stat.h>
#import <os/log.h>
#import <dirent.h>
#import "kern_utils.h"
#import "common.h"

FILE *log_file = NULL;

#define CS_OPS_STATUS           0       /* return status */
int csops(pid_t pid, unsigned int  ops, void * useraddr, size_t usersize);

const char *blacklist[] = {
    "diagnosticd",    // syslog
    "logd",       // logd - things that log when this is starting end badly so...
    "jailbreakd",               // gotta call to this
    NULL
};

bool is_blacklisted(const char *proc) {
    for (const char **entry = blacklist; *entry; entry++) {
        if (strstr(proc, *entry)) {
            DEBUGLOG("blacklisted");
            return true;
        }
    }
    DEBUGLOG("not blacklisted");
    return false;
}

bool MSunrestrict0(mach_port_t task) {
    bool do_sandbox = false;
    char pathbuf[PROC_PIDPATHINFO_MAXSIZE];
    bzero(pathbuf, sizeof(pathbuf));

    pid_t ourpid;
    if ( (pid_for_task(task, &ourpid) != 0) || ourpid <= 1) {
        return true;
    }
    proc_pidpath(ourpid, pathbuf, sizeof(pathbuf));

    if (strcmp(pathbuf, "/usr/libexec/xpcproxy")==0) {
        return true;
    }

    if (!is_blacklisted(pathbuf)) {
        DEBUGLOG("%s: (%d) fixing up", pathbuf, ourpid);
        fixup(ourpid);
    } else {
        DEBUGLOG("%s: blacklisted", pathbuf);
    }
    return true;
}

bool MSrevalidate0(mach_port_t task) {
    char pathbuf[PROC_PIDPATHINFO_MAXSIZE];
    bzero(pathbuf, sizeof(pathbuf));

    pid_t ourpid;
    if ( (pid_for_task(task, &ourpid) != 0) || ourpid <= 1) {
        return true;
    }
    proc_pidpath(ourpid, pathbuf, sizeof(pathbuf));

    if (strcmp(pathbuf, "/usr/libexec/xpcproxy")==0) {
        return true;
    }

    uint32_t status;
    if (csops(ourpid, CS_OPS_STATUS, &status, sizeof(status)) < 0)
       return true;

    uint64_t proc = proc_find(ourpid);
    if (proc == 0) {
        DEBUGLOG("failed to find proc for pid %d!", ourpid);
        return true;
    }

    if ((status & CS_VALID) == 0)
        fixup_cs_valid(proc);

    return true;
}
