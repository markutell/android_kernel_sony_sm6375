#!/usr/bin/env python3
"""
Pasang hook manual KernelSU (CONFIG_KSU_MANUAL_HOOK) ke source kernel 5.4.

Hook yang dipasang (mengikuti panduan hook manual ReSukiSU, varian "scope-minimized"):
  fs/exec.c      -> ksu_handle_execveat   (do_execve + compat_do_execve)
  fs/open.c      -> ksu_handle_faccessat  (syscall faccessat)
  fs/stat.c      -> ksu_handle_stat       (newfstatat/fstatat64),
                    ksu_handle_newfstat_ret (+ fstat64_ret kalau ada)
  kernel/reboot.c-> ksu_handle_sys_reboot (syscall reboot)

Hook input/setuid/read TIDAK dipasang manual: diaktifkan lewat opsi
KSU_MANUAL_HOOK_AUTO_*_HOOK di defconfig.

Sifat skrip:
  - ATOMIC : semua anchor harus cocok dulu; kalau ada satu yang gagal, tidak ada file diubah.
  - IDEMPOTENT: file yang sudah berisi hook dilewati.
Pakai:  python3 ksu_manual_hooks.py [root_kernel]   (default: direktori saat ini)
        lalu cek dengan `git diff` sebelum commit.
"""
import re
import sys
from pathlib import Path

ROOT = Path(sys.argv[1] if len(sys.argv) > 1 else ".")
INC = "#include <linux/ksu_manual_hooks.h>\n"

HEADER = """\
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
"""


class AnchorError(Exception):
    pass


def wrap(code):
    return "#ifdef CONFIG_KSU_MANUAL_HOOK\n" + code + "#endif\n"


def add_include(text, path):
    if "ksu_manual_hooks.h" in text:
        return text
    m = re.search(r"^#include", text, re.M)
    if not m:
        raise AnchorError(f"{path}: tidak ada baris #include")
    return text[: m.start()] + INC + text[m.start():]


def insert_before_each(text, pattern, block, expected, path, label):
    ms = list(re.finditer(pattern, text, re.M))
    if len(ms) not in expected:
        raise AnchorError(
            f"{path}: anchor '{label}' ditemukan {len(ms)}x, diharapkan {sorted(expected)}x"
        )
    for m in reversed(ms):
        text = text[: m.start()] + block + text[m.start():]
    return text


def insert_before_return(text, func_regex, block, path, label, optional=False):
    """Sisipkan block sebelum '\treturn error;' pertama setelah header fungsi."""
    m = re.search(func_regex + r".*?\n(?=\treturn error;\n)", text, re.S)
    if not m:
        if optional:
            return text
        raise AnchorError(f"{path}: fungsi/anchor '{label}' tidak ditemukan")
    return text[: m.end()] + block + text[m.end():]


def process_exec(text, path):
    text = add_include(text, path)
    block = wrap(
        "\tksu_handle_execveat((int *)AT_FDCWD, &filename, &argv, &envp, 0);\n"
    )
    return insert_before_each(
        text,
        r"^\treturn do_execveat_common\(AT_FDCWD, filename, argv, envp, 0\);$",
        block,
        {2},
        path,
        "do_execve & compat_do_execve",
    )


def process_open(text, path):
    text = add_include(text, path)
    block = wrap("\tksu_handle_faccessat(&dfd, &filename, &mode, NULL);\n")
    return insert_before_each(
        text,
        r"^\treturn do_faccessat\(dfd, filename, mode\);$",
        block,
        {1},
        path,
        "syscall faccessat",
    )


def process_stat(text, path):
    text = add_include(text, path)
    block = wrap("\tksu_handle_stat(&dfd, &filename, &flag);\n")
    ms = list(
        re.finditer(
            r"^SYSCALL_DEFINE4\((?:newfstatat|fstatat64),[^{]*\{\n[^}]*?"
            r"(?=\terror = vfs_fstatat\(dfd, filename, &stat, flag\);\n)",
            text,
            re.M,
        )
    )
    if len(ms) not in (1, 2):
        raise AnchorError(
            f"{path}: newfstatat/fstatat64 ditemukan {len(ms)}x, diharapkan 1-2x"
        )
    for m in reversed(ms):
        text = text[: m.end()] + block + text[m.end():]
    text = insert_before_return(
        text,
        r"SYSCALL_DEFINE2\(newfstat,",
        wrap("\tksu_handle_newfstat_ret(&fd, &statbuf);\n"),
        path,
        "newfstat",
    )
    text = insert_before_return(
        text,
        r"SYSCALL_DEFINE2\(fstat64,",
        wrap("\tksu_handle_fstat64_ret(&fd, &statbuf);\n"),
        path,
        "fstat64",
        optional=True,
    )
    return text


def process_reboot(text, path):
    text = add_include(text, path)
    m = re.search(r"SYSCALL_DEFINE4\(reboot,.*?\n\tint ret = 0;\n", text, re.S)
    if not m:
        raise AnchorError(f"{path}: anchor 'int ret = 0;' di syscall reboot tidak ditemukan")
    block = "\n" + wrap("\tksu_handle_sys_reboot(magic1, magic2, cmd, &arg);\n")
    return text[: m.end()] + block + text[m.end():]


JOBS = [
    ("fs/exec.c", "ksu_handle_execveat", process_exec),
    ("fs/open.c", "ksu_handle_faccessat", process_open),
    ("fs/stat.c", "ksu_handle_stat", process_stat),
    ("kernel/reboot.c", "ksu_handle_sys_reboot", process_reboot),
]


def main():
    new_texts = {}
    errors = []
    for rel, marker, fn in JOBS:
        p = ROOT / rel
        if not p.is_file():
            errors.append(f"{rel}: file tidak ada")
            continue
        text = p.read_text()
        if marker in text:
            print(f"[skip] {rel}: sudah ada hook ({marker})")
            continue
        try:
            new_texts[rel] = fn(text, rel)
        except AnchorError as e:
            errors.append(str(e))

    if errors:
        print("GAGAL, tidak ada file yang diubah:", file=sys.stderr)
        for e in errors:
            print("  - " + e, file=sys.stderr)
        print(
            "\nKirim potongan fungsi yang gagal (sed -n 'AWAL,AKHIRp' file) supaya anchor-nya disesuaikan.",
            file=sys.stderr,
        )
        sys.exit(1)

    hdr = ROOT / "include/linux/ksu_manual_hooks.h"
    hdr.write_text(HEADER)
    print(f"[ok] {hdr.relative_to(ROOT)}")
    for rel, text in new_texts.items():
        (ROOT / rel).write_text(text)
        print(f"[ok] {rel}")
    print("\nSelesai. Cek dengan: git diff --stat && git diff")


if __name__ == "__main__":
    main()
