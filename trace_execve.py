from bcc import BPF

# 内核态代码：追踪execve系统调用
bpf_code = """
#include <uapi/linux/ptrace.h>

BPF_PERF_OUTPUT(events);

struct data_t {
    u32 pid;
    char comm[16];
};

int trace_execve(struct pt_regs *ctx) {
    struct data_t data = {};
    data.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
"""

# 加载eBPF程序
b = BPF(text=bpf_code)
b.attach_kprobe(event="__x64_sys_execve", fn_name="trace_execve")

# 用户态：打印输出
def print_event(cpu, data, size):
    event = b["events"].event(data)
    print(f"PID: {event.pid}  进程: {event.comm.decode()}")

b["events"].open_perf_buffer(print_event)
print("正在监控 execve 系统调用... Ctrl+C 退出")

while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        break