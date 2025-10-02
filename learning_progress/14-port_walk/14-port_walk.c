#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/sched/signal.h>
#include <linux/fdtable.h>
#include <linux/fs.h>
#include <linux/net.h>
#include <net/sock.h>
#include <net/inet_sock.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>


MODULE_LICENSE("GPL");

#define Pname "open_ports"

static struct proc_dir_entry *entry;

static int show_sockets(struct seq_file *m , void *v)
{
    struct task_struct *task;

    rcu_read_lock();
    for_each_process(task) {
        struct files_struct *files = task->files;
        struct fdtable *fdt;
        unsigned int i;

        if (!files)
            continue;

        spin_lock(&files->file_lock);
        fdt = files_fdtable(files);
        for (i = 0; i < fdt->max_fds; i++) {
            struct file *f = fdt->fd[i];
            struct socket *sock;
            struct sock *sk;
            struct inet_sock *inet;

            if (!f || !S_ISSOCK(file_inode(f)->i_mode))
                continue;

            sock = sock_from_file(f);
            if (!sock)
                continue;

            sk = sock->sk;
            if (!sk)
                continue;

            if (sk->sk_family != AF_INET && sk->sk_family != AF_INET6)
                continue;

            inet = inet_sk(sk);
            seq_printf(m,"pid=%d comm=%s source port=%u destination port=%u\n",
                   task->pid, task->comm,
                   ntohs(inet->inet_sport), ntohs(inet->inet_dport));
        }
        spin_unlock(&files->file_lock);
    }
    rcu_read_unlock();
    return 0;
}

static int proc_open(struct inode *inode,struct file *file){
	return single_open(file,show_sockets,NULL);
}

static const struct proc_ops my_ops = {
	.proc_open = proc_open,
	.proc_read = seq_read,
	.proc_release = single_release,
};

static int __init kports_init(void)
{
    printk(KERN_INFO "Kernel port walk : init\n");
    entry = proc_create(Pname , 0 ,NULL,&my_ops);
    if(!entry){
    	return -ENOMEM;
    }
    
    return 0;
}

static void __exit kports_exit(void)
{
	proc_remove(entry);
	printk(KERN_INFO "Kernel port walk: exit\n");
}

module_init(kports_init);
module_exit(kports_exit);
