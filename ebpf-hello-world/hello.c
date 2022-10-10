#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/resource.h>

// bpf 通过libbpf提供
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
/*
This header is a program-specific header generated from the compiled BPF object file. 
The generated skeleton contains a collection of functions and data structures to help load the BPF program 
and work with its maps. 
It also contains a generated structure that describes the program that will be loaded.
生成命令 
2-1  
bpftool gen skeleton hello.bpf.o > hello.skel.h

包含函数 hello_bpf_* 
The open function opens and parses the BPF program, maps and global variables
*/
#include "hello.skel.h"


// 读取打印的消息
void read_trace_pipe(void)
{
	int trace_fd;

	trace_fd = open("/sys/kernel/debug/tracing/trace_pipe", O_RDONLY, 0);
	if (trace_fd < 0)
		return;

	while (1) {
		static char buf[4096];
		ssize_t sz;

		sz = read(trace_fd, buf, sizeof(buf) - 1);
		if (sz > 0) {
			buf[sz] = 0;
			puts(buf);
		}
	}
}

int main(void) 
{
	struct hello_bpf *obj;
	int err = 0;

	struct rlimit rlim = {
		.rlim_cur = 512UL << 20,
		.rlim_max = 512UL << 20,
	};

	err = setrlimit(RLIMIT_MEMLOCK, &rlim);
	if (err) {
		fprintf(stderr, "failed to change rlimit\n");
		return 1;
	}


	obj = hello_bpf__open();
	if (!obj) {
		fprintf(stderr, "failed to open and/or load BPF object\n");
		return 1;
	}

	err = hello_bpf__load(obj);
	if (err) {
		fprintf(stderr, "failed to load BPF object %d\n", err);
		goto cleanup;
	}

	err = hello_bpf__attach(obj);
	if (err) {
		fprintf(stderr, "failed to attach BPF programs\n");
		goto cleanup;
	}

	read_trace_pipe();

cleanup:
	hello_bpf__destroy(obj);
	return err != 0;
}

// 2-2 命令
// clang -g -O2 -Wall -I . -c hello.c -o hello.o

// 2-3
// clang -Wall -O2 -g hello.o libbpf/build/libbpf.a -lelf -lz -o hello