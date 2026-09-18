
#!/usr/bin/python3
from bcc import BPF

bpf_code = """
#include <uapi/linux/ptrace.h>

struct data_t {
    u32 pid;
    char comm[16];
    char filename[256];
};

BPF_PERF_OUTPUT(events);

int trace_openat(struct pt_regs *ctx) {
    struct data_t data = {};

    data.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    const char *filename = (const char *)PT_REGS_PARM2(ctx);
    bpf_probe_read_user_str(&data.filename, sizeof(data.filename), filename);

    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
"""

b = BPF(text=bpf_code)
b.attach_kprobe(event="do_sys_openat2", fn_name="trace_openat")

def print_event(cpu, data, size):
    event = b["events"].event(data)
    print(f"PID: {event.pid}  进程: {event.comm.decode()}  文件: {event.filename.decode()}")

b["events"].open_perf_buffer(print_event)
print("监控文件打开... Ctrl+C 退出")

while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        break