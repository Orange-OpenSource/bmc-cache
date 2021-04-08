# Software Name : bmc-cache
# SPDX-FileCopyrightText: Copyright (c) 2021 Orange
# SPDX-License-Identifier: LGPL-2.1-only
#
# This software is distributed under the
# GNU Lesser General Public License v2.1 only.
#
# Author: Yoann GHIGOFF <yoann.ghigoff@orange.com> et al.
#
#	To use this Makefile: clang and llvm must be installed,
#	kernel sources available under ./linux and libbpf statically
#	compiled in Linux source tree.
#
#	bmc_kern.c depends on kernel headers and bpf_helpers.h
#	bmc_user.c depends on libbpf

LINUX_PATH ?= ./linux
LINUX_TOOLS_PATH = $(LINUX_PATH)/tools
LINUX_LIB_PATH = $(LINUX_TOOLS_PATH)/lib
LIBBPF_PATH = $(LINUX_LIB_PATH)/bpf

TARGETS += bmc

CLANG ?= clang-9
LLC ?= llc-9
CC := gcc

KERN_SOURCES = ${TARGETS:=_kern.c}
USER_SOURCES = ${TARGETS:=_user.c}
KERN_OBJECTS = ${KERN_SOURCES:.c=.o}
USER_OBJECTS = ${USER_SOURCES:.c=.o}

LIBBPF = $(LIBBPF_PATH)/libbpf.a

CFLAGS := -g -O2 -Wall
CFLAGS += -I.
CFLAGS += -I$(LINUX_LIB_PATH)
CFLAGS += -I$(LINUX_TOOLS_PATH)/include/uapi

LDFLAGS ?= -L$(LIBBPF_PATH) -l:libbpf.a -lelf $(USER_LIBS)

NOSTDINC_FLAGS := -nostdinc -isystem $(shell $(CC) -print-file-name=include)
ARCH=$(shell uname -m | sed 's/x86_64/x86/' | sed 's/i386/x86/')

LINUXINCLUDE := -I$(LINUX_PATH)/arch/$(ARCH)/include
LINUXINCLUDE += -I$(LINUX_PATH)/arch/$(ARCH)/include/uapi
LINUXINCLUDE += -I$(LINUX_PATH)/arch/$(ARCH)/include/generated
LINUXINCLUDE += -I$(LINUX_PATH)/arch/$(ARCH)/include/generated/uapi
LINUXINCLUDE += -I$(LINUX_PATH)/include
LINUXINCLUDE += -I$(LINUX_PATH)/include/uapi
LINUXINCLUDE += -I$(LINUX_PATH)/include/generated/uapi
LINUXINCLUDE += -I$(LINUX_PATH)/tools/testing/selftests/bpf
LINUXINCLUDE += -include $(LINUX_PATH)/include/linux/kconfig.h
LINUXINCLUDE += -include $(LINUX_PATH)/samples/bpf/asm_goto_workaround.h

EXTRA_CFLAGS=-Werror

###

all: dependencies $(TARGETS) $(KERN_OBJECTS)

.PHONY: clean dependencies verify_cmds verify_target_bpf $(CLANG) $(LLC)

clean:
	@find . -type f \
		\( -name '*~' \
		-o -name '*.ll' \
		-o -name '*.bc' \
		-o -name 'core' \) \
		-exec rm -vf '{}' \;
	rm -f $(TARGETS)
	rm -f $(KERN_OBJECTS)
	rm -f $(USER_OBJECTS)
	rm -f $(OBJECT_LOADBPF)

dependencies: verify_target_bpf

linux-src:
	@if ! test -d $(LINUX_PATH)/; then \
		echo "ERROR: Need kernel source code to compile against" ;\
		echo "(Cannot open directory: $(LINUX_PATH))" ;\
		exit 1; \
else true; fi

linux-src-libbpf: linux-src
	@if ! test -d $(LIBBPF_PATH); then \
		echo "WARNING: Compile against local kernel source code copy" ;\
		echo "       and specifically tools/lib/bpf/ "; \
else true; fi

verify_cmds: $(CLANG) $(LLC)
	@for TOOL in $^ ; do \
		if ! (which -- "$${TOOL}" > /dev/null 2>&1); then \
			echo "*** ERROR: Cannot find LLVM tool $${TOOL}" ;\
			exit 1; \
		else true; fi; \
	done

verify_target_bpf: verify_cmds
	@if ! (${LLC} -march=bpf -mattr=help > /dev/null 2>&1); then \
		echo "*** ERROR: LLVM (${LLC}) does not support 'bpf' target" ;\
		echo "   NOTICE: LLVM version >= 3.7.1 required" ;\
		exit 2; \
	else true; fi

$(LIBBPF): $(wildcard $(LIBBPF_PATH)/*.[ch] $(LIBBPF_PATH)/Makefile)
	make -C $(LIBBPF_PATH)

# Compiling of eBPF restricted-C code with LLVM
#  clang option -S generated output file with suffix .ll
#   which is the non-binary LLVM assembly language format
#   (normally LLVM bitcode format .bc is generated)
#
# Use -Wno-address-of-packed-member as eBPF verifier enforces
# unaligned access checks where necessary
#
$(KERN_OBJECTS): %.o: %.c
	$(CLANG) -S $(NOSTDINC_FLAGS) $(LINUXINCLUDE) $(EXTRA_CFLAGS) \
	    -D__KERNEL__ -D__ASM_SYSREG_H -D__BPF_TRACING__ \
	    -D__TARGET_ARCH_$(ARCH) \
	    -Wno-unused-value -Wno-pointer-sign \
	    -Wno-compare-distinct-pointer-types \
	    -Wno-gnu-variable-sized-type-not-at-end \
	    -Wno-tautological-compare \
	    -Wno-unknown-warning-option \
	    -Wno-address-of-packed-member \
	    -O2 -g -emit-llvm -c $< -o ${@:.o=.ll}
	$(LLC) -march=bpf -filetype=obj -o $@ ${@:.o=.ll}

$(TARGETS): %: %_user.c $(OBJECTS) $(LIBBPF)
	$(CC) $(CFLAGS) $(OBJECTS) -o $@ $< $(LIBBPF) $(LDFLAGS)
