// bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
#include "vmlinux.h"

// https://www.man7.org/linux/man-pages/man7/bpf-helpers.7.html
// git clone https://github.com/libbpf/libbpf && cd libbpf/src/
// make BUILD_STATIC_ONLY=1 OBJDIR=../build/libbpf DESTDIR=../build INCLUDEDIR= LIBDIR= UAPIDIR= install
// cp cp -r libbpf/build/bpf . 
// 到当前目录通过路径调用bpf/bpf_helpers.h
#include <bpf/bpf_helpers.h>

// SEC 就是 bpf_helpers.h 中的一个预处理器 宏
/*
 * 详细的挂载点在 /sys/kernel/debug/tracing/events/syscalls/sys_enter_execve
可以方便的在目录下面查看相关的ebpf程序挂载的挂载点 /sys/kernel/debug/tracing/events
 * 
 */
SEC("tracepoint/syscalls/sys_enter_execve")

// 函数名称可以随便起
// 函数参数是挂载点事件传递过来的参数
int tracepoint__syscalls__sys_enter_execve(struct trace_event_raw_sys_enter *ctx)
{
	// 将字符串写在这个文件里面 /sys/kernel/debug/tracing/trace_pipe
	bpf_printk("Hello world!\n");
	// When execution ends, the BPF program returns the integer value to the kernel, 
	// which then decides what action to take based on the returned value 
	// (e.g., drop or forward a network packet).
	return 0;
}

char LICENSE[] SEC("license") = "GPL";

// 编译改程序
// 1-1
// clang -g -O2 -target bpf -D__TARGET_ARCH_x86_64 -I . -c hello.bpf.c -o hello.bpf.o