# An attempt at writing a "how to do eBPF stuff for research"-guide


## Programming model
eBPF employs an event based programming model. Combined with running in-kernel, this makes it a bit hard to debug or even verify whether a program has been executed at all. 


Steps of running an eBPF program and "getting output":
1. Write the program
2. Set up any maps the program will need using the bpf-syscall. 
3. Use the bpf-syscall to load the program and attach it to a hook-point, e.g. a socket.
4. Trigger the program to execute by activating the hook, e.g. by sending a packet to the socket the program is attached to. 
5. Read any output from the map, dumped by the program.
6. Use `bpftool` to dump the `xlated` and/or `jited` versions of the program. 

## Write eBPF using C-Macros
The "easiest" way to begin writing (and executing) eBPF programs is to use C-macros. 

Use the scaffolding in `testbed.c`. 
It will help you set up (a) map(s), load a program, trigger the program to execute and read any dumped values from the map(s). 

eBPF programs are arrays of bytes, each instruction being 8 bytes, wrapped in `struct bpf_insn`. 



## Write eBPF using Haskell (ebpf-tools)
TODO

## Write eBPF using C (clang)
TODO

## "Debugging" 
TODO

- bpf-tool
- "custom" C-programs to dump stuff like maps
