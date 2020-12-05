# keyling
The 10 hour experience of working with the qiling framework

#### Why qiling?
* Useful for partial emulation and code introspection
* Capable of hooking instructions, syscalls, library calls
* Built on top of notable unicorn, capstone, keystone engines
* Made to be extendable, python3

#### Why not qiling?
* MIPS16 support is not in Unicorn (yet)

#### Hour 1 
* Created prototype boilerplate code for hooking a syscall, redirecting unhandled codes to the original handler.

#### Hour 2
* Created example C code for testing how to implement a missing syscall.

#### Hour 3
* Implemented a missing syscall, showing an example of how to hijack and modify the data returned.
