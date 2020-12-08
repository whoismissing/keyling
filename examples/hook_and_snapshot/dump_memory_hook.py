#!/usr/bin/python3
'''
This example shows several capabilities of
using the qiling framework:
1. hooking an arbitrary address to run some python code
2. saving and restoring a snapshot with partial execution
   to run a memory dump function on a code state
'''
import signal
import time

from qiling import *
from yaspin import yaspin

ARGV = [ "./wm_vm" ]
ROOTFS = "/" 
ENV = { "DEBUG":"1" }

DumpMemory_beg = 0x00400f3c
DumpMemory_end = 0x00401358
IOBufferGetBit_beg = 0x00400c72
MemWrite_end = 0x00400f0f

SPINNER = yaspin()

def signal_handler(signal, frame):
    SPINNER.stop()
    print("\n[EXIT] Got CTRL-C, entering debugger...")
    import pdb; pdb.set_trace()

def dump_memory(ql):
    save_state = ql.save(mem=True, reg=False, cpu_context=True)

    time.sleep(1)

    dm = Qiling(ARGV, ROOTFS, env=ENV)
    dm.restore(save_state)
    dm.run(begin = DumpMemory_beg, end = DumpMemory_end) 
    dm.emu_stop()

    ql.IOBufferGetBitHit = False

def DumpMemory_hook(ql):
    if ql.IOBufferGetBitHit:
        ql.nprint("\n+++++++++\n")
        ql.nprint("DumpMemory hook")
        ql.nprint("+++++++++\n")
        dump_memory(ql)

def IOBufferGetBit_hook(ql):
    ql.IOBufferGetBitHit = True

def main():
    ql = Qiling(ARGV, ROOTFS, env=ENV)
    ql.filter = [ "stdout", "stderr" ]
    ql.IOBufferGetBitHit = False
    ql.hook_address(callback=IOBufferGetBit_hook, address=IOBufferGetBit_beg)
    ql.hook_address(callback=DumpMemory_hook, address=MemWrite_end)

    SPINNER.start()

    ql.run()

signal.signal(signal.SIGINT, signal_handler)

main()

