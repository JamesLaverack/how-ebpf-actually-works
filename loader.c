// SPDX-License-Identifier: BSD-3-Clause
#include <byteswap.h>
#include <errno.h>
#include <fcntl.h>
#include <gelf.h>
#include <libelf.h>
#include <linux/bpf.h>
#include <linux/perf_event.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <syscall.h>
#include <unistd.h>

int main() {
  printf("Loading the world's worst eBPF program.\n");

  // Load the eBPF bytecode from disk
  int objfile_fd = open("./trace.bpf.o", O_RDONLY); 
  if (objfile_fd < 0) {
    printf("Failed to open file for reading\n");
    return 1;
  }
  printf("obj file fd:%d/n", objfile_fd);

  // Parse it as an ELF file
  elf_version(EV_CURRENT);
  Elf *elf = elf_begin(objfile_fd, ELF_C_READ, NULL);
  if (!elf) {
    printf("Failed to open elf file\n");
    return 1;
  }

  // Load the ELF header
  GElf_Ehdr elf_header;
  if (gelf_getehdr(elf, &elf_header) != &elf_header) {
    printf("Failed to read header from ELF file\n");
    return 1;
  }
  printf("Elf File had %d sections:\n", elf_header.e_shnum);
  
  // Iterate over sections
  Elf_Data *data;
  for (int i = 0; i < elf_header.e_shnum; i++) {
    Elf_Scn *section = elf_getscn(elf, i);
    GElf_Shdr section_header;
    gelf_getshdr(section, &section_header);
    char *section_name = elf_strptr(elf, elf_header.e_shstrndx, section_header.sh_name);
    printf("    section %d. Name %s\n", i, section_name);
    if (strncmp(".text", section_name, 5) == 0) {
      data = elf_getdata(section, 0);
    }
  }
  if (!data) {
    printf("Failed to find .text section\n");
    return 1;
  }
  printf("Loaded eBPF data, len:%d\n", (int) data->d_size);
  
  // Load it into the kernel
  char log_buf[10240];
  char *license = "Dual BSD/GPL";
  struct bpf_insn *insns = (struct bpf_insn*)data->d_buf;
  union bpf_attr attr = {
    .prog_type = BPF_PROG_TYPE_TRACEPOINT,
    .insns = (__u64)insns,
    .insn_cnt = data->d_size / sizeof(struct bpf_insn),
    .license = (__u64)license,
    .log_buf = (__u64)log_buf,
    .log_size = 10240,
    .log_level = 1, 
  };

  // Print it out for debug reasons
  printf("eBPF instructions:\n");
  for (int i=0; i<attr.insn_cnt; i++) {
    struct bpf_insn insn = ((struct bpf_insn*)attr.insns)[i];
    printf("    code:0x%02X, dst:0x%01X, src:0x%01X, off:0x%04X, imm:0x%08X\n", insn.code, insn.dst_reg, insn.src_reg, insn.off, insn.imm);
  }

  int bpf_fd = syscall(__NR_bpf, BPF_PROG_LOAD, &attr, sizeof(attr));
  printf("bpf log: %s\n", log_buf);
  if (bpf_fd == -1) {
    printf("bpf syscall ret:%d\n", bpf_fd);
    printf("errno:%d, strerr:%s\n", errno, strerror(errno));
    return 1;
  } else {
    printf("bpf fd:%d\n", bpf_fd);
  }

  // Open up the tracepoint
  int tracepoint_id_fd = open("/sys/kernel/debug/tracing/events/syscalls/sys_enter_execve/id", O_RDONLY);
  if (tracepoint_id_fd < 0) {
    printf("Failed to open tracepoint file for reading\n");
    return 1;
  }
  printf("tracepoint_id_fd:%d\n", tracepoint_id_fd);
  char tracepoint_id_buf[1024];
  read(tracepoint_id_fd, tracepoint_id_buf, 1024);
  close(tracepoint_id_fd);
  printf("tracepoint_id_buf:%s\n", tracepoint_id_buf);
  __u64 tracepoint_id = atoi(tracepoint_id_buf);
  printf("tracepoint_id:%lld\n", tracepoint_id);
   
  // Open the tracepoint
  struct perf_event_attr perf_attr = {
    .type = PERF_TYPE_TRACEPOINT,
    .config = tracepoint_id, 
  };
  int tracepoint_fd = syscall(__NR_perf_event_open, &perf_attr, getpid(), -1, -1, 0);
  printf("tracepoint_fd:%d\n", tracepoint_fd);

  // Attach an eBPF program
  int ret = ioctl(tracepoint_fd, PERF_EVENT_IOC_SET_BPF, bpf_fd);  
  if (ret == -1) {
    printf("errno:%d, strerr:%s\n", errno, strerror(errno));
    return 1;
  }
  printf("Attached program to tracepoint\n");

  // Loop forever
  while (1) {};
}
