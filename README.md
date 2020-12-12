# keyling
The 10 hour experience of working with the qiling framework

---

#### Why qiling?
* Useful for partial emulation and code introspection
* Capable of hooking instructions, syscalls, library calls
* Built on top of notable unicorn, capstone, keystone engines
* Made to be extendable, python3

---

#### Why not qiling?
* MIPS16 support is not in Unicorn (yet)
* Emulation is really slow

---

#### Hour 1 
* Created prototype boilerplate code for hooking a syscall, redirecting unhandled codes to the original handler.

---

#### Hour 2
* Created example C code for testing how to implement a missing syscall.

---

#### Hour 3
* Implemented a missing syscall, showing an example of how to hijack and modify the data returned.

---

#### Hours 4 - 7
* Tried qiling on a ctf challenge hijacking stdin, emulation of the code example ended up being very slow.

---

#### Hour 8
* Implemented qiling partial emulation snapshot on ctf code example.

---

#### Hour 9
* Cleaned up code for hook and snapshot example.

---

#### Hour 10
* Created markdown learning materials

---

#### Emulate an executable with qiling

To get started, create a `Qiling()` object.

All the member variables and instance methods for the Qiling() core object can be viewed in the source code @ `qiling/qiling/core.py::Qiling`

To run an executable binary, required arguments are: 

`ql = Qiling(argv, rootfs)` 

where an example of argv is `["program", "arg1", "arg2"]` and rootfs points to the root `/` file system containing the libraries and loader. Generally for x86 linux, you can use `/` but for stuff like embedded, you'll point to the squashfs.

---

#### Emulate shellcode with qiling

To run raw shellcode, required arguments are:

`ql = Qiling(shellcode, ostype, archtype)` where shellcode is a byte-string.

ostype options are `"linux", "macos", "windows", "uefi", "freebsd"`

archtype options are `"x8664", "x86", "arm", "arm64", "mips"`

---

#### Qiling setup

Now, set up options for the qiling instance with various instance methods on the Qiling() object

Typically, this includes setting up `hijacks` and `hooks` before starting the emulation.

---

#### Hijacks

Hijacks are points in the program that are intercepted to introduce new code.

They can be applied to stdio (stdin, stdout), to library calls, and to syscalls.

---

#### Hijacking a syscall

`ql.set_syscall(syscall_code, python_syscall_hook)` - a syscall's name can be provided instead of the syscall code if it has been implemented and exists in the qiling core code.

The python syscall hook will have the prototype of:

`def syscall_hook(ql, original_syscall_args, *args, **kw):`

Depending on the original syscall's prototype definition, determines the number of parameters.

Qiling's core linux syscall implementations can be viewed @ `qiling/qiling/os/posix/syscall/*.py`

An example hook prototype for hijacking the 32-bit socketcall syscall:

`def sys_socketcall_hook(ql, socketcall_call, socketcall_args, *args, **kw):`

---

#### Hijacking a syscall (entry / exit)

Pass constants `from qiling.const import *` to `ql.set_syscall()` for example:

hijack on syscall entry: `ql.set_syscall(syscall_code, syscall_hook, QL_INTERCEPT.ENTER)`

hijack on syscall exit: `ql.set_syscall(syscall_code, syscall_hook, QL_INTERCEPT.EXIT)`

---

#### Hijacking a library call

For example, libc functions can be hooked and stubbed out with python code with:

`ql.set_api('puts', python_hook)`

The prototype of the python hook seems to only contain the ql object though, so args are grabbed within the hook:

```
def puts_hook(ql):
    addr = ql.os.function_arg[0]
    print("Hijack Libc puts(%s)" % ql.mem.string(addr))
```

Similarly, `ql.set_api` can be used to hijack on library call entry and exit with the same constants and format as the syscall hijack.

---

#### Hooking

Specific code points can be hooked to run python code. 

Many hook options exist, the notable ones are:

`ql.hook_address(python_hook, program_address)` - run python hook when program (code) address is hit. corresponding hook prototype is `def python_hook(ql):`

`ql.hook_code(python_hook)` - run python hook on every instruction execution. corresponding hook prototype is `def python_hook(ql, address, size):`

---

#### Binary Patching and asm compiling

Patch a library loaded by the binary:

`ql.patch(memory_address, byte-string-patch, file_name = library_name)`

Patch the binary itself:

`ql.patch(memory_address, byte-string-patch)`

Compile assembly with keystone to pass to ql.patch():

`ql.compile(ASM, ql.archtype)`

---

#### Save and restore a snapshot

The state of memory, registers, and cpu context can be saved on a qiling emulator session and restored on another session for partial execution.

**save state**:

`save_state = ql.save(mem= True, reg= True, fd= True, cpu_ctx= False)`

**restore state**:

`ql.restore(save_state)` - ql does not have to be the same Qiling() object, it can be another.

**partial execution**:

`ql.run(begin = 0xFE, end = 0xFF)` - run the qiling emulator beginning code at the begin address and finishing at the end address. optionally timeout and count can be passed as parameters as well

---

#### Real world Experience

Mileage may vary depending on core architecture and syscall support from the qiling framework.

Takeaway is to figure out the level of effort needed for emulating a particular target.

* Do you want to achieve full emulation of the binary?
* Do you only need to emulate a particular function in the code?

---

#### Errata

For running windows stuff, have to collect dlls with `qiling/examples/scripts/dllscollector.bat` and dump registry since those files are not provided for the rootfs because of legal licensing reasons.

---

#### References

* [Official Docs](https://docs.qiling.io/en/latest/)
* [Source code](https://github.com/qilingframework/qiling)

