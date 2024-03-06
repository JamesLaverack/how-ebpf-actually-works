# SPDX-License-Identifier: BSD-3-Clause
TARGETS = loader trace.bpf.o

.PHONY: all
all: $(TARGETS)

%.bpf.o: %.bpf.c 
	clang -target bpf -Wall -O2 -c "$<" -o "$@" -I/usr/include/x86_64-linux-gnu/

%: %.c 
	clang -Wall -O2 "$<" -o "$@" -l elf -l bpf

.PHONY: clean
clean:
	rm -rf $(TARGETS)

