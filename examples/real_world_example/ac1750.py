#!/usr/bin/python3
"""
When run from the beginning with qltool with

qltool run -f squashfs-root/usr/sbin/uhttpd --rootfs squashfs-root/ -m --qdb --args -f -p 12345

Current Emulation Errors are:
[!] 0x7758a254: syscall ql_syscall_epoll_create number = 0x1098(4248) not implemented
[!] 0x775d289c: syscall ql_syscall_waitpid number = 0xfa7(4007) not implemented
Error: No sockets bound, unable to continue

In the attempt to emulate only the uh_cgi_request function:
    Partial execution requires saving and restoring the memory state

TODO: 
* Develop automation to figure out level of effort for emulation:
1. Identify the architecture of the binary
2. Identify whether the code is multithreaded
3. Figure out all syscalls used in the code (binary + libraries)
4. Figure out which of the appearing syscalls are implemented in qiling
"""
import argparse
import time

from qiling import *
from qiling.debugger.qdb import QlQdb as Qdb

ARGV = [ "/home/pen/ac7_v5/ac7_v5.extracted/squashfs-root/usr/sbin/uhttpd", "-f", "-p", "12345" ]
ROOTFS = "/home/pen/ac7_v5/ac7_v5.extracted/squashfs-root"

uh_cgi_request_beg = 0x004084c8 # UNUSED
uh_cgi_request_end = 0x00408a1c

main_before_first_call = 0x004026f4

uh_cgi_request_call_malloc = 0x00408510
uh_cgi_request_call_execl = 0x00408a94
uh_cgi_request_call_printf = 0x00408aac

NR_EPOLL_CREATE = 4248
NR_WAITPID = 4007

def enter_qdb(ql):
    '''Convenience function for debugging when in PDB'''
    dbg = Qdb(ql)
    dbg.interactive()

def print_info(*args):
    CGREEN = '\33[32m'
    CRESET = '\33[0m'
    print(CGREEN, end="")
    for arg in args:
        print(args, end="")
    print(CRESET)

#### HOOKS - BEGIN ####

def save_state_hook(ql, *args, **kw):
    '''Hook to save emulation state and stop the emulator'''
    print_info("Saving state, stopping emulation before the call to memset in main")
    save_state = ql.save(mem=True, reg=False, cpu_context=True)
    ql.save_state = save_state
    ql.emu_stop()

def execl_hook(ql, *args, **kw):
    '''Hook to set the args for the call to execl'''
    print_info("Entering execl hook, setting args")
    argv = ql.reg.a0
    args = b"/usr/bin/yes\x00"
    ql.mem.write(argv, args)
    ql.reg.a1 = ql.reg.a0
    ql.reg.a2 = 0x00

def printf_hook(ql, *args, **kw):
    '''Hook to set the args for the call to printf'''
    print_info("Entering printf hook, setting args")
    data = b"How did the hipster burn his tongue?\x00" 
    arg2_data = "😎 He drank his coffee before it was cool...\x00".encode("utf-8")
    ql.mem.write(ql.reg.s0, data)
    ql.mem.write(ql.reg.v0, arg2_data)

def debug_hook(ql, *args, **kw):
    '''Hook to enter QDB debugger'''
    ql.nprint("debug hook")
    ql.emu_stop()
    ql.console = True
    print_info("Entering QDB debugger")
    ql.clear_hooks()
    dbg = Qdb(ql)
    dbg.interactive()

#### HOOKS - END ####

#### SYSCALLS - BEGIN ####

def ql_syscall_epoll_create(ql, *args, **kw):
    print_info("Entering epoll_create hook")
    print_info("args = ", args)
    print_info("kw = ", kw)

def ql_syscall_waitpid(ql, *args, **kw):
    print_info("Entering waitpid hook")
    print_info("args = ", args)
    print_info("kw = ", kw)

def ql_syscall_fork(ql, *args, **kw):
    print_info("Entering fork hook")
    print_info("args = ", args)
    print_info("kw = ", kw)

#### SYSCALLS - END ####

def main():
    parser = argparse.ArgumentParser(description="qiling ac1750 wip emulator")
    parser.add_argument("-d", "--debug", required=False, default=False, action="store_true",
                        help="run with debugging output")
    parser.add_argument("hook", help="Select a hook to run, options are: [ execl, printf ]")
    args = parser.parse_args()
    debug = None
    if args.debug:
        debug = "debug"

    ql = Qiling(ARGV, ROOTFS, profile="linux.ql", output=debug)
    ql.filter = [ "stdout", "stderr" ]

    ql.hook_address(callback = save_state_hook, address = main_before_first_call)
    # Stub out unimplemented syscalls
    ql.set_syscall(NR_EPOLL_CREATE, ql_syscall_epoll_create)
    ql.set_syscall(NR_WAITPID, ql_syscall_waitpid)

    ql.run()

    time.sleep(1)

    print_info("Spinning up uh_cgi_request emulation")
    cgi = Qiling(ARGV, ROOTFS, profile="linux.ql", output=None)
    cgi.restore(ql.save_state)
    cgi.debug_stop = True

    cgi.hook_address(callback = debug_hook, address = uh_cgi_request_call_malloc)
    cgi.set_syscall("fork", ql_syscall_fork)

    if args.hook == "execl":
        cgi.hook_address(callback = execl_hook, address = uh_cgi_request_call_execl)
        cgi.run(begin = uh_cgi_request_call_execl, end = uh_cgi_request_end)

    elif args.hook == "printf":
        cgi.hook_address(callback = printf_hook, address = uh_cgi_request_call_printf)
        cgi.run(begin = uh_cgi_request_call_printf, end = uh_cgi_request_end)

main()

