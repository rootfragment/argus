#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/kprobes.h>
#include <linux/unistd.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/slab.h>

MODULE_LICENSE("GPL");

#define PROC_NAME "syscall_integrity"

static unsigned long (*kallsyms_lookup_name_ptr)(const char *name);
static unsigned long *sys_call_table;
static unsigned long *golden_sys_call_table;

static struct proc_dir_entry *proc_entry;


static int resolve_kallsyms(void)
{
    struct kprobe kp = {
        .symbol_name = "kallsyms_lookup_name"
    };

    int ret = register_kprobe(&kp);
    if (ret < 0)
        return ret;

    kallsyms_lookup_name_ptr = (void *)kp.addr;
    unregister_kprobe(&kp);

    if (!kallsyms_lookup_name_ptr)
        return -ENOENT;

    return 0;
}


static int syscall_integrity_show(struct seq_file *m, void *v)
{
    int i;
    int tampered = 0;
    char sym_name[KSYM_NAME_LEN];

    for (i = 0; i < NR_syscalls; i++) {
        if (sys_call_table[i] != golden_sys_call_table[i])
            tampered++;
    }

    if (!tampered) {
        seq_printf(m, "0\n");
        return 0;
    }

    seq_printf(m, "-1\n");

    for (i = 0; i < NR_syscalls; i++) {
        if (sys_call_table[i] != golden_sys_call_table[i]) {

            memset(sym_name, 0, sizeof(sym_name));
            sprint_symbol(sym_name,
                          (unsigned long)golden_sys_call_table[i]);

            seq_printf(m, "%s\n", sym_name);
        }
    }

    return 0;
}

static int syscall_integrity_open(struct inode *inode, struct file *file)
{
    return single_open(file, syscall_integrity_show, NULL);
}

static const struct proc_ops proc_fops = {
    .proc_open    = syscall_integrity_open,
    .proc_read    = seq_read,
    .proc_lseek   = seq_lseek,
    .proc_release = single_release,
};

static int __init lkm_init(void)
{
    int ret;

    ret = resolve_kallsyms();
    if (ret)
        return ret;

    sys_call_table =
        (unsigned long *)kallsyms_lookup_name_ptr("sys_call_table");

    if (!sys_call_table)
        return -ENOENT;

    golden_sys_call_table =
        kmalloc_array(NR_syscalls, sizeof(unsigned long), GFP_KERNEL);
    if (!golden_sys_call_table)
        return -ENOMEM;

    memcpy(golden_sys_call_table,
           sys_call_table,
           NR_syscalls * sizeof(unsigned long));

    proc_entry = proc_create(PROC_NAME, 0444, NULL, &proc_fops);
    if (!proc_entry) {
        kfree(golden_sys_call_table);
        return -ENOMEM;
    }

    pr_info("syscall_integrity module loaded\n");
    return 0;
}

static void __exit lkm_exit(void)
{
    proc_remove(proc_entry);
    kfree(golden_sys_call_table);
    pr_info("syscall_integrity module unloaded\n");
}

module_init(lkm_init);
module_exit(lkm_exit);
