#include<linux/kernel.h>
#include<linux/init.h>
#include<linux/module.h>
#include<linux/proc_fs.h>
#include<linux/string.h>
#include<linux/seq_file.h>
#include<linux/uaccess.h>
#include<linux/sched/signal.h>

#define PROC_NAME "proc_demo"
#define MAX_CMD_LEN 32

static bool show_process;

static int proc_show(struct seq_file *m,void *v){

	struct task_struct *task;
	
	if(!show_process){
		seq_printf(m, "Echo 'process' into %s\n",PROC_NAME); 
		return 0;
	}
	seq_puts(m,"PID\tCOMM\n");
	for_each_process(task){
		seq_printf(m, "%d\t%s\n",task->pid,task->comm);
	}
	return 0;
}

static int proc_open(struct inode *inode, struct file *file){
	return single_open(file,proc_show,NULL);
}

static ssize_t proc_write(struct file *file, const char __user *buffer, size_t count, loff_t *pos){
	char kbuf[MAX_CMD_LEN];
	
	if( count == 0 || count >= MAX_CMD_LEN)
		return -EINVAL;
		
	if(copy_from_user(kbuf,buffer,count))
		return -EFAULT;
		
	kbuf[count] = '\0';
	strim(kbuf);
	
	if(strcmp(kbuf, "process")==0){
		show_process = true;
		pr_info("proc_demo : process listing enabled");
	}
	else{
		show_process = false;
		pr_info("proc_demo : process listing disabled");
	}
	return count;
}

static const struct proc_ops myops ={
	.proc_open = proc_open,
	.proc_read = seq_read,
	.proc_lseek = seq_lseek,
	.proc_release = single_release,
	.proc_write = proc_write,
};

static int __init proc_demo_init(void){
	proc_create(PROC_NAME,0666,NULL,&myops);
	pr_info("Module loaded\nProc file created\n");
	return 0;
}
static void __exit proc_demo_exit(void){
	remove_proc_entry(PROC_NAME,NULL);
	pr_info("Module unloaded\nProc file removed\n");
}

module_init(proc_demo_init);
module_exit(proc_demo_exit);
MODULE_LICENSE("GPL");
