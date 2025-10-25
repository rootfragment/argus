#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/sched.h>
#include <linux/spinlock.h>
#include <linux/ktime.h>
#include <linux/slab.h>
#include <linux/cred.h>

MODULE_LICENSE("GPL");

#define MAX_ENTRIES 1024
#define MAX_COMM 16
#define PROC_NAME "syscall_monitor"
#define MAX_PROBES 16
#define MAX_SYM 32

static const char *targets[] = {
    "__x64_sys_init_module", "__x64_sys_finit_module",
    "__x64_sys_delete_module", "__x64_sys_execve",
    "__x64_sys_openat", "__x64_sys_ptrace",
    "__x64_sys_ioctl", "__x64_sys_mmap",
    "__x64_sys_clone", "__x64_sys_setuid",
    "__x64_sys_read", "__x64_sys_write", "__x64_sys_close", NULL
};

struct log_entry {
    u64 ts;
    pid_t pid;
    pid_t tgid;
    uid_t uid;
    char comm[MAX_COMM];
    char syscall[MAX_SYM];
} __packed;

static struct log_entry buf[MAX_ENTRIES];
static u64 head;
static spinlock_t lock;
static struct proc_dir_entry *pe;

static struct kprobe probes[MAX_PROBES];
static int nprobes;

static bool clear_on_read = false;

static void log_event(const char *name) {
    unsigned long flags;
    struct log_entry *e;
    spin_lock_irqsave(&lock, flags);
    e = &buf[head % MAX_ENTRIES];
    e->ts = ktime_get_real_seconds();
    e->pid = current->pid;
    e->tgid = current->tgid;
    e->uid = from_kuid(&init_user_ns, current_uid());
    strncpy(e->comm, current->comm, MAX_COMM - 1);
    e->comm[MAX_COMM - 1] = '\0';
    strncpy(e->syscall, name, MAX_SYM - 1);
    e->syscall[MAX_SYM - 1] = '\0';
    head++;
    spin_unlock_irqrestore(&lock, flags);
}

static int pre_handler(struct kprobe *p, struct pt_regs *r) {
    if (p && p->symbol_name)
        log_event(p->symbol_name);
    return 0;
}

static int register_probes(void) {
    int i, registered = 0;
    for (i = 0; targets[i] && registered < MAX_PROBES; i++) {
        probes[registered].symbol_name = targets[i];
        probes[registered].pre_handler = pre_handler;
        if (register_kprobe(&probes[registered]) == 0)
            registered++;
    }
    nprobes = registered;
    return 0;
}

static int show_proc(struct seq_file *m, void *v) {
    struct log_entry *tmp = NULL;
    unsigned long flags;
    unsigned int n, start;
    size_t entry_size = sizeof(struct log_entry);
    int i;
    spin_lock_irqsave(&lock, flags);
    if (head == 0) {
        spin_unlock_irqrestore(&lock, flags);
        return 0;
    }
    if (head < MAX_ENTRIES) {
        n = (unsigned int)head;
        start = 0;
    } else {
        n = MAX_ENTRIES;
        start = (unsigned int)(head % MAX_ENTRIES);
    }
    spin_unlock_irqrestore(&lock, flags);
    tmp = kmalloc_array(n, entry_size, GFP_KERNEL);
    if (!tmp)
        return -ENOMEM;
    spin_lock_irqsave(&lock, flags);
    memcpy(tmp, buf, n * entry_size);
    spin_unlock_irqrestore(&lock, flags);
    for (i = 0; i < (int)n; i++) {
        unsigned int idx = (start + i) % n;
        seq_printf(m, "%llu,%d,%d,%u,%s,%s\n",
                   (unsigned long long)tmp[idx].ts,
                   tmp[idx].pid,
                   tmp[idx].tgid,
                   tmp[idx].uid,
                   tmp[idx].comm,
                   tmp[idx].syscall);
    }
    kfree(tmp);
    if (clear_on_read) {
        spin_lock_irqsave(&lock, flags);
        head = 0;
        spin_unlock_irqrestore(&lock, flags);
    }
    return 0;
}

static int open_proc(struct inode *inode, struct file *file) {
    return single_open(file, show_proc, NULL);
}

static const struct proc_ops fops = {
    .proc_open    = open_proc,
    .proc_read    = seq_read,
    .proc_lseek   = seq_lseek,
    .proc_release = single_release,
};


static int __init init_rk(void) {
    int ret = 0;
    spin_lock_init(&lock);
    head = 0;
    pe = proc_create(PROC_NAME, 0444, NULL, &fops);
    if (!pe)
        return -ENOMEM;
    register_probes();
    pr_info("syscall_monitor: loaded and outputting to /proc/%s\n", PROC_NAME);
    return ret;
}

static void __exit exit_rk(void) {
    int i;
    for (i = 0; i < nprobes; i++)
        unregister_kprobe(&probes[i]);
    if (pe)
        proc_remove(pe);
    pr_info("syscall_monitor: unloaded\n");
}

module_init(init_rk);
module_exit(exit_rk);
