#!/usr/bin/python3
'''
Some syscalls are unimplemented in the emulator.

This is an example for how to hijack and implement
those syscalls.
'''

from qiling import *
from qiling.const import QL_ARCH

def sys_socketcall_hook(ql, socketcall_code, socketcall_args, *args, **kw):
    '''
    Some x86 socketcall codes are not yet implemented in
    qiling/qiling/os/posix/syscall/net.py::ql_syscall_socketcall

    We hijack the socketcall syscall to handle some of the unimplemented calls
    and call the original qiling socketcall handler otherwise.
    '''
    regreturn = QL_ARCH.X86
    SOCKETCALL_SYS_GETSOCKNAME = 6

    if socketcall_code == SOCKETCALL_SYS_GETSOCKNAME:
        print("custom socketcall getsockname", hex(socketcall_args), args, kw)
        regreturn = 6969
    else: # original qiling socketcall handler
        from qiling.os.posix.syscall.net import ql_syscall_socketcall
        ql_syscall_socketcall(ql, socketcall_code, socketcall_args, *args, **kw)

    ql.os.definesyscall_return(regreturn)

def main():
    '''
    '''
    elf = "./getsockname"
    rootfs = "/"
    ql = Qiling([elf, "127.0.0.1", "6969"], rootfs, archtype="x86", ostype="linux", output="debug")

    # Insert hooks to implement or stub out syscalls as needed
    #ql.set_syscall("socketcall", sys_socketcall_hook)

    ql.run()

main()

