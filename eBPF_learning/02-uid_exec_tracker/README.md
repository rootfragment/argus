# Overview of the eBPF Program Execution Counter

This program uses eBPF (extended Berkeley Packet Filter) and the BCC (BPF Compiler Collection) framework to create a system-wide monitor for program executions. It tracks every time a new program is launched via the `execve` system call and maintains a count of how many times each user (identified by their UID) has executed a program. The collected data is stored in an eBPF map, and the Python script periodically reads this map to print a live report of execution counts per user.

The core of the solution is a C program that gets compiled and attached to the `execve` syscall using a kernel probe (kprobe). This C code is responsible for identifying the user ID of the process triggering the syscall and incrementing a counter associated with that user in a hash map. The user-space Python script then provides the control logic: it loads the eBPF program, attaches it to the correct kernel function, and enters an infinite loop to read and display the collected statistics every two seconds.

# Line-by-Line Explanation

1.  **`from bcc import BPF`**: This line imports the main `BPF` class from the `bcc` library, which is the central component for interacting with the eBPF subsystem in the kernel.

2.  **`from time import sleep`**: This imports the `sleep` function, which is used to add a delay in the main loop, controlling how frequently the script polls for new data.

3.  **`program = """..."""`**: This multi-line string contains the C code for our eBPF program.
    *   **`BPF_HASH(counter_table);`**: This is a BCC macro that declares a hash map named `counter_table`. This map will be used to store the execution counts, with the user ID (UID) as the key and the count as the value.
    *   **`int hello(void *ctx)`**: This is the C function that will be executed every time the `execve` syscall is triggered.
    *   **`u64 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;`**: This line retrieves the current user and group ID. The `& 0xFFFFFFFF` operation is a bitwise AND that isolates the lower 32 bits, which corresponds to the user ID (UID).
    *   **`u64 *p = counter_table.lookup(&uid);`**: The script looks up the current UID in the `counter_table`. If an entry for this UID exists, `p` will be a pointer to its value; otherwise, it will be `NULL`.
    *   **`if (p != 0) { counter = *p; }`**: This checks if a counter for the UID already exists. If it does, the existing value is read into the `counter` variable.
    *   **`counter++;`**: The counter is incremented.
    *   **`counter_table.update(&uid, &counter);`**: The new, incremented value of `counter` is stored back into the `counter_table` with the UID as the key. This will either update the existing entry or create a new one if it's the first time this UID has been seen.

4.  **`b = BPF(text=program)`**: This line compiles the C code from the `program` string into eBPF bytecode and loads it into the kernel. The `b` object represents the loaded eBPF program and provides an interface to interact with it.

5.  **`syscall = b.get_syscall_fnname("execve")`**: This helper function from BCC retrieves the correct, architecture-specific name of the kernel function that implements the `execve` system call.

6.  **`b.attach_kprobe(event=syscall, fn_name="hello")`**: This attaches our C function `hello` to the `execve` syscall. Now, every time any process on the system calls `execve`, our `hello` function will be executed in the kernel.

7.  **`while True:`**: This starts an infinite loop to continuously monitor the system.

8.  **`sleep(2)`**: The script pauses for two seconds before proceeding. This determines the polling interval for reading the data.

9.  **`table = b.get_table("counter_table")`**: Inside the loop, this line retrieves a reference to the `counter_table` eBPF map from the kernel.

10. **`for k, v in table.items():`**: This loop iterates over all the key-value pairs currently in the `counter_table`.
    *   **`print(f"uid {k.value} : {v.value}")`**: For each entry in the map, it prints the user ID (`k.value`) and the corresponding execution count (`v.value`). This provides a snapshot of the number of programs each user has run since the script was started.
