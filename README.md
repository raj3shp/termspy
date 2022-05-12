# termspy (Terminal Spy)

A simple implementation of a terminal keylogger in C using ptrace.

TLDR;
- Attach to terminal/bash process with `ptrace` syscall
- capture ASCII from all `write` syscalls and print to stdout

### Usage:

Identify pid of a process running a shell or a terminal and run termspy on it.

```
gcc termspy.c -o termspy

./termspy 1234
```
Since we use `ptrace` syscall, termspy must have CAP_SYS_PTRACE capability. Depending upon the distribution, user needs target user's or root privileges. See [ptrace_scope](https://www.kernel.org/doc/Documentation/security/Yama.txt)

`/proc/sys/kernel/yama/ptrace_scope`

- Redhat  `0` (a process can PTRACE_ATTACH to any other process running under the same uid)
- Ubuntu  `1` (restricted ptrace: a process must have a predefined relationship with the inferior it wants to call PTRACE_ATTACH on)

### Details:

As a defender or an attacker with access to a compromised Linux system one can leverage [`ptrace`](https://man7.org/linux/man-pages/man2/ptrace.2.html) to spy on user's terminal activity and potentially get hold of secret information.

The `ptrace` syscall provides a means by which one process may observe and control the execution of another process, and examine and change the tracee's memory and registers.

This functionality can be easily exploited to craft keyloggers in Linux user space. Using this techniques requires termspy to have same privilege as the target user or root.

To achieve this, we attach to the target process using ptrace, intercept every syscall and look for `write` syscalls. We're specifically interested in the second and third arguments passed to `write(fd, data, len)` which are stored in RSI and RDX registers respectively on 64-bit systems. By reading the data in the registers we can capture all ASCII characters.

By implementing [`auditd`](https://linux.die.net/man/8/auditd) to monitor usage of `ptrace` syscall, we can detect such attacks effectively. `ptrace` is rarely used in regular applications and mostly used by debuggers such as `gdb`, `strace` or `lldb`. Unless you are expecting heavy usage of debuggers in your live systems, it's very good idea to monitor usage of all `ptrace` syscalls and verify their legitamacy. 

_Inspiration: https://www.linuxjournal.com/article/6100_
