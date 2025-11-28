# eBPF Program Execution Flow (Simplified Explanation)

## Overview
This example demonstrates how a minimal eBPF program is loaded, attached to a kernel event, and how its output is captured.

---

## Helper Function Usage
The eBPF program makes use of a helper function called `bpf_trace_printk()`.  
Helper functions allow eBPF programs to interact with the system in restricted, safe ways.  
In this example, the helper simply writes a message to the kernel’s trace buffer.

---

## Defining the eBPF Program
The eBPF C code is stored inside a Python string.  
BCC automatically compiles this C code into eBPF bytecode, so no manual compilation is required.  
The program is provided to BCC when creating a `BPF` object:

- A BPF object handles compilation, loading, and management of the eBPF program.

---

## Attaching the Program to a Kernel Event
The eBPF program must be attached to a specific event in order to run.  
In this case, it is attached to the `execve` system call, which is triggered whenever a new program is executed.

Because kernel function names differ across architectures, BCC provides a helper that returns the correct function name for the system:

- The program uses this resolved syscall name to attach a kprobe.
- A kprobe causes the eBPF program to run each time the kernel function is executed.

---

## Reading Output
Once attached, the eBPF program runs whenever a new executable starts.  
Its output is written to the kernel trace buffer.

A trace-reading function continuously reads and prints these messages until the program is manually stopped.

---

## Summary
1. The eBPF program is defined in C within a Python string.  
2. BCC compiles and loads it into the kernel.  
3. The program is attached to the `execve` syscall via a kprobe.  
4. Whenever a new executable runs, the eBPF code is executed.  
5. Trace output is streamed live from the kernel.

