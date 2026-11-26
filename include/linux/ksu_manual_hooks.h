#ifndef _LINUX_KSU_MANUAL_HOOKS_H
#define _LINUX_KSU_MANUAL_HOOKS_H

#ifdef CONFIG_KSU_MANUAL_HOOK
#include <linux/types.h>
#include <linux/compiler.h>

struct filename;
struct stat;
struct stat64;

extern int ksu_handle_execveat(int *fd, struct filename **filename_ptr,
                   void *argv, void *envp, int *flags);
extern int ksu_handle_faccessat(int *dfd, const char __user **filename_user,
                int *mode, int *flags);
extern int ksu_handle_stat(int *dfd, const char __user **filename_user,
               int *flags);
extern void ksu_handle_newfstat_ret(unsigned int *fd,
                    struct stat __user **statbuf_ptr);
extern void ksu_handle_fstat64_ret(unsigned int *fd,
                   struct stat64 __user **statbuf_ptr);
extern int ksu_handle_sys_reboot(int magic1, int magic2, unsigned int cmd,
                 void __user **arg);
#endif /* CONFIG_KSU_MANUAL_HOOK */

#endif /* _LINUX_KSU_MANUAL_HOOKS_H */
