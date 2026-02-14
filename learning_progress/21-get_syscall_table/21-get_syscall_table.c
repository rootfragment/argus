#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/kprobes.h>
#include <linux/unistd.h>

MODULE_LICENSE("GPL");

static unsigned long (*kallsyms_lookup_name_ptr)(const char *name);
static int resolve_kallsyms(void)
{
    struct kprobe kp = {
        .symbol_name = "kallsyms_lookup_name"
    };

    int ret = register_kprobe(&kp);
    if (ret < 0) {
        pr_err("LKM: register_kprobe failed: %d\n", ret);
        return ret;
    }

    kallsyms_lookup_name_ptr = (void *)kp.addr;
    unregister_kprobe(&kp);

    if (!kallsyms_lookup_name_ptr) {
        pr_err("LKM: Failed to resolve kallsyms_lookup_name\n");
        return -ENOENT;
    }

    pr_info("LKM: kallsyms_lookup_name resolved at %px\n",
            kallsyms_lookup_name_ptr);

    return 0;
}

static int __init lkm_init(void)
{
    unsigned long *sys_call_table;
    int ret;

    pr_info("LKM: Module loaded\n");

    ret = resolve_kallsyms();
    if (ret)
        return ret;

    sys_call_table =
        (unsigned long *)kallsyms_lookup_name_ptr("sys_call_table");

    if (!sys_call_table) {
        pr_err("LKM: sys_call_table not found\n");
        return -ENOENT;
    }

    pr_info("LKM: sys_call_table at %px\n", sys_call_table);

#ifdef __NR_read
    pr_info("sys_reaed  -> %px\n",
            (void *)sys_call_table[__NR_read]);
#endif

#ifdef __NR_write
    pr_info("sys_write -> %px\n",
            (void *)sys_call_table[__NR_write]);
#endif

#ifdef __NR_execve
    pr_info("sys_execve -> %px\n",
            (void *)sys_call_table[__NR_execve]);
#endif

    return 0;
}

static void __exit lkm_exit(void)
{
    pr_info("LKM: Module unloaded\n");
}

module_init(lkm_init);
module_exit(lkm_exit);

