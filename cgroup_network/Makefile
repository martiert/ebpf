# this is for using distribution provided bpftool
BPFTOOL=$(shell which bpftool)

CFLAGS:=-O3 -iquote out/include

CFLAGS+=$(shell pkg-config --cflags libbpf)
CFLAGS+=$(shell pkg-config --cflags fmt)
LDFLAGS=$(shell pkg-config --libs libbpf)
LDFLAGS+=$(shell pkg-config --libs fmt)

BPFFLAGS:=${CFLAGS} -g
BPFFLAGS+=-target bpf
BPFFLAGS+=-fno-stack-protector -Wno-unused-command-line-argument

.PHONY: all
all: out/exec

out/include:
	@mkdir --parent $@

out/include/vmlinux.h: Makefile out/include
	@echo "[VMLINUX] $@"
	@${BPFTOOL} btf dump file /sys/kernel/btf/vmlinux format c > $@

out/%.bpf.o: %.bpf.c out/include/vmlinux.h event.h
	@echo "[BPF]     $@"
	@clang ${BPFFLAGS} -c -o $@ $<

out/include/exec.skel.h: out/exec.bpf.o
	@echo "[SKEL]    $@"
	@${BPFTOOL} gen skeleton $< name exec > $@

out/%.o: %.cpp out/include/exec.skel.h event.h
	@echo "[CC]      $@"
	@clang++ ${CFLAGS} -std=c++23 -c -o $@ $<

out/exec: out/exec.o out/poller.o out/cgroup.o
	@echo "[LD]      $@"
	@clang++ $^ ${LDFLAGS} -o $@

run: out/exec
	@echo "[RUN]     $<"
	@sudo $<

clean:
	@echo "[CLEAN] out"
	@-rm -rf out
