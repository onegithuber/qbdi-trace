//
// Created by chenfangzheng on 2025/7/22.
//
#include "dealSyscall.h"
extern std::string retFuncName;
extern uint64_t parameter1;
extern uint64_t parameter2;
extern uint64_t parameter3;
std::string dealSyscall(uint64_t SyscallNumber, uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5, uint64_t arg6){
    std::string logtext;
    //syscall都会处理参数，如果遇到了没有处理过的syscall调用号，在这里添加逻辑
    switch (SyscallNumber) {
        case SYS_openat:
            logtext = parse_openat(arg1, reinterpret_cast<const char *>(arg2), arg3, arg4) + "\n";
            break;
        case SYS_read:
            logtext = parse_read(arg1, arg2, arg3);
            retFuncName = "read";
            parameter2 = arg2;
            break;
        case SYS_close:
            logtext = fmt::format("close({:#x})\n", arg1);
            break;
        case SYS_write:
            logtext = "write";
            break;
        case SYS_gettid:
            logtext = "gettid(void)";
            break;
        case SYS_mprotect:
            logtext = parse_mprotect(arg1, arg2, arg3) + "\n";
            break;
        case SYS_process_vm_readv:
            //ssize_t process_vm_readv(pid_t pid, const struct iovec *local_iov, unsigned long liovcnt, const struct iovec *remote_iov, unsigned long riovcnt, unsigned long flags);
            /* pid 进程pid
             * local_iov 本地缓冲区
             * local_iovcnt 本地缓冲区的元素个数
             * remote_iov 远程缓冲区
             * remote_iovcnt 远程缓冲区的元素个数
             * flags
            */
            logtext = parse_process_vm_readv(arg1, arg2, arg3, arg4, arg5, arg6) + "\n";
            break;
        case SYS_process_vm_writev:
            //ssize_t process_vm_writev(pid_t pid, const struct iovec *local_iov, unsigned long liovcnt, const struct iovec *remote_iov, unsigned long riovcnt, unsigned long flags);
            /* pid 进程pid
             * local_iov 本地缓冲区
             * local_iovcnt 本地缓冲区的元素个数
             * remote_iov 远程缓冲区
             * remote_iovcnt 远程缓冲区的元素个数
             * flags 必须为0
            */
            logtext = parse_process_vm_writev(arg1, arg2, arg3, arg4, arg5, arg6) + "\n";
            break;
        // Add more syscalls as needed
        case SYS_mmap: //222
            logtext = parse_mmap(arg1, arg2, (int)arg3, (int)arg4, (int)arg5, arg6);
            retFuncName = "mmap";
            break;
        case SYS_gettimeofday: //169
            logtext = "gettimeofday()\n";
            break;
        case SYS_madvise: //233
            logtext = fmt::format("madvise({:#x},{:#x},{})\n", arg1, arg2, (int)arg3);
            break;
        case SYS_getpid: //172
            logtext = "getpid()\n";
            break;
        case SYS_getppid: //173
            logtext = "getppid()\n";
            break;
        case SYS_fstat: //80
            logtext = parse_fstat(arg1, arg2) + "\n";
            break;
        case SYS_lseek: //62
            logtext = parse_lseek(arg1, arg2, arg3) + "\n";
            break;
        case SYS_faccessat: //48
            logtext = parse_faccessat(arg1, reinterpret_cast<const char *>(arg2), (int)arg3, (int)arg4) + "\n";
            break;
        case SYS_newfstatat: //79
            logtext = parse_newfstatat(arg1, reinterpret_cast<const char *>(arg2), arg3, (int)arg4) + "\n";
            break;
        default:
            logtext = "Not compatible syscall number: " + std::to_string(SyscallNumber) + "\n";
            break;
    }
    return logtext;
}