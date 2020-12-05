#!/usr/bin/python3
'''
Some syscalls are unimplemented in the emulator.

This is an example for how to hijack and implement
those syscalls.
'''
import argparse
import ipaddress
import struct

from qiling import *
from qiling.const import QL_ARCH
from qiling.os.posix.syscall.net import ql_syscall_socketcall
from qiling.os.posix.syscall.socket import ql_syscall_getsockname

OVERWRITE = False

def my_syscall_getsockname(ql, getsockname_sockfd, getsockname_addr, getsockname_addrlen, *args, **kw):
    '''
    ql_syscall_getsockname is originally implemented in qiling/qiling/os/posix/syscall/socket.py
    and can be imported with:

    from qiling.os.posix.syscall.socket import ql_syscall_getsockname
    '''
    if getsockname_sockfd < 256 and ql.os.fd[getsockname_sockfd] != 0: 
        host = '80.8.13.5'
        port = 42069
        data = struct.pack("<h", int(ql.os.fd[getsockname_sockfd].family))
        data += struct.pack(">H", port)
        data += ipaddress.ip_address(host).packed
        addrlen = ql.mem.read(getsockname_addrlen, 4)
        addrlen = ql.unpack32(addrlen)
        data = data[:addrlen]
        ql.mem.write(getsockname_addr, data)
        regreturn = 0
    else:
        regreturn = -1

    ql.nprint("getsockname(%d, %x, %x) = %d" %(getsockname_sockfd, getsockname_addr, getsockname_addrlen, regreturn))
    ql.os.definesyscall_return(regreturn)

def sys_socketcall_hook(ql, socketcall_call, socketcall_args, *args, **kw):
    '''
    Some x86 socketcall codes are not yet implemented in
    qiling/qiling/os/posix/syscall/net.py::ql_syscall_socketcall

    We hijack the socketcall syscall to handle some of the unimplemented calls
    and call the original qiling socketcall handler otherwise.
    '''
    global OVERWRITE
    SOCKETCALL_SYS_GETSOCKNAME = 6

    if socketcall_call == SOCKETCALL_SYS_GETSOCKNAME:
        ql.nprint("socketcall(%d, %x)" % (socketcall_call, socketcall_args))
        socketcall_sockfd = ql.unpack(ql.mem.read(socketcall_args, ql.pointersize))
        socketcall_addr = ql.unpack(ql.mem.read(socketcall_args + ql.pointersize, ql.pointersize))
        socketcall_addrlen = ql.unpack(ql.mem.read(socketcall_args + ql.pointersize * 2, ql.pointersize))

        if OVERWRITE:
            my_syscall_getsockname(ql, socketcall_sockfd, socketcall_addr, socketcall_addrlen)
        else:
            ql_syscall_getsockname(ql, socketcall_sockfd, socketcall_addr, socketcall_addrlen)
    else: # original qiling socketcall handler
        ql_syscall_socketcall(ql, socketcall_call, socketcall_args, *args, **kw)

def main():
    parser = argparse.ArgumentParser(description="qiling syscall hooking example")
    parser.add_argument("-b", "--bin", required=True, nargs="+",
                        help="binary file to examine")
    parser.add_argument("-r", "--rootfs", required=False, default="/",
                        help="root filesystem for binary library and loader")
    parser.add_argument("-o", "--overwrite-syscall", required=False, default=False, action="store_true",
                        help="overwrite the syscall with the hook")
    parser.add_argument("-d", "--debug", required=False, default=False, action="store_true",
                        help="run with debugging output")
    args = parser.parse_args()

    debug = None
    if args.debug:
        debug = "debug"

    global OVERWRITE
    if args.overwrite_syscall:
        OVERWRITE = True

    ql = Qiling(args.bin, args.rootfs, archtype="x86", ostype="linux", output=debug)

    # Insert hooks to implement or stub out syscalls as needed
    ql.set_syscall("socketcall", sys_socketcall_hook)

    ql.filter = [ "stdout" ]

    ql.run()

main()

