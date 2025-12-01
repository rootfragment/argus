from bcc import BPF
from time import sleep
program = """
BPF_HASH(counter_table);
int hello(void *ctx){
	u64 uid;
	u64 counter = 0;
	u64 *p;
	
	uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
	p = counter_table.lookup(&uid);
	if(p!=0){
		counter = *p;
	}
	counter++;
	counter_table.update(&uid,&counter);
	return 0;
	}
"""
b = BPF(text=program)
syscall = b.get_syscall_fnname("execve")
b.attach_kprobe(event=syscall,fn_name="hello")

while True:
	sleep(2)
	table = b.get_table("counter_table")
	for k ,v in table.items():
		print(f"uid {k.value} : {v.value}")
