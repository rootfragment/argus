#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/seq_file.h>
#include <linux/proc_fs.h>
#include <linux/rcupdate.h>

static int modules_show(struct seq_file *m, void *v)
{
    struct module *mod;

    rcu_read_lock();
    list_for_each_entry_rcu(mod, THIS_MODULE->list.prev, list) {
        seq_printf(m, "%s\n", mod->name);
    }
    rcu_read_unlock();

    return 0;
}

static int modules_open(struct inode *inode, struct file *file)
{
    return single_open(file, modules_show, NULL);
}

static const struct proc_ops proc_fops = {
    .proc_open = modules_open,
    .proc_read = seq_read,
    .proc_lseek = seq_lseek,
    .proc_release = single_release,
};

static int __init mymodule_init(void)
{
    proc_create("loaded_mods", 0, NULL, &proc_fops);
    pr_info("Trusted module helper loaded\n");
    return 0;
}

static void __exit mymodule_exit(void)
{
    remove_proc_entry("trusted_modules", NULL);
    pr_info("MODULE LISTER LOADED\n");
}

MODULE_LICENSE("GPL");

module_init(mymodule_init);
module_exit(mymodule_exit);
