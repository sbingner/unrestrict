#ifndef sandbox_h
#define sandbox_h

#include <CoreFoundation/CoreFoundation.h>
#include <mach/mach.h>

uint64_t extension_create_file(const char* path, uint64_t nextptr);
void extension_add(uint64_t ext, uint64_t sb, const char* desc);
int has_file_extension(uint64_t sb, const char* path);

#endif
