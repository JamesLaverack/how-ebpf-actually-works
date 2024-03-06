// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Based on examples/c/minimal.bpf.c from libbpf-bootstrap, Copyright (c) 2020 Facebook
#define BPF_NO_GLOBAL_DATA 1

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

int print_pid(void *ctx)
{
  int pid = bpf_get_current_pid_tgid() >> 32;
  bpf_printk("Saw syscall from PID %d\n", pid);
  return 0;
}

