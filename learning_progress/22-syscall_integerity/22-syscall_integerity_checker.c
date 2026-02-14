#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/kprobes.h>
#include <linux/unistd.h>
#include <linux/timer.h>
#include <linux/slab.h>

#define CHECK_INTERVAL_SECONDS 5

MODULE_LICENSE("GPL");

static unsigned long *syscall_table_addr;
static unsigned long *golden_syscall_table;
static struct timer_list check_timer;
static unsigned long (*kallsyms_lookup_name_ptr)(const char *name);

static int resolve_kallsyms(void)
{
    struct kprobe kp = {
        .symbol_name = "kallsyms_lookup_name"
    };

    int ret = register_kprobe(&kp);
    if (ret < 0) {
        pr_err("Syscall integerity checker: register_kprobe failed for kallsyms_lookup_name: %d\n", ret);
        return ret;
    }
    kallsyms_lookup_name_ptr = (void *)kp.addr;
    unregister_kprobe(&kp);
    if (!kallsyms_lookup_name_ptr) {
        pr_err("Syscall integerity checker: Failed to resolve kallsyms_lookup_name\n");
        return -ENOENT;
    }
    return 0;
}

static void check_syscall_table(struct timer_list *t)
{
    int i;
    for (i = 0; i < NR_syscalls; i++) {
        if (syscall_table_addr[i] != golden_syscall_table[i]) {
            pr_warn("Syscall integerity checker: Syscall %d tampered! Original: %px, New: %px\n",
                    i, (void *)golden_syscall_table[i], (void *)syscall_table_addr[i]);        
        }
    }
    mod_timer(&check_timer, jiffies + msecs_to_jiffies(CHECK_INTERVAL_SECONDS * 1000));
}

static int __init Syscall integerity checker_detector_init(void)
{
    int ret;

    pr_info("Syscall integerity checker: Loading detector module.\n");

    ret = resolve_kallsyms();
    if (ret)
        return ret;
    syscall_table_addr = (unsigned long *)kallsyms_lookup_name_ptr("sys_call_table");
    if (!syscall_table_addr) {
        pr_err("Syscall integerity checker: sys_call_table not found\n");
        return -ENOENT;
    }
    pr_info("Syscall integerity checker: Found sys_call_table at %px\n", syscall_table_addr);

    golden_syscall_table = kmalloc(sizeof(unsigned long) * NR_syscalls, GFP_KERNEL);
    if (!golden_syscall_table) {
        pr_err("Syscall integerity checker: Failed to allocate memory for golden table.\n");
        return -ENOMEM;
    }

    memcpy(golden_syscall_table, syscall_table_addr, sizeof(unsigned long) * NR_syscalls);
    pr_info("Syscall integerity checker: Created syscall table baseline.\n");

    timer_setup(&check_timer, check_syscall_table, 0);
    mod_timer(&check_timer, jiffies + msecs_to_jiffies(CHECK_INTERVAL_SECONDS * 1000));

    pr_info("Syscall integerity checker: Detector initialized and running.\n");
    return 0;
}

static void __exit Syscall integerity checker_detector_exit(void)
{
    del_timer_sync(&check_timer);
    kfree(golden_syscall_table);
    pr_info("Syscall integerity checker: Detector unloaded.\n");
}

module_init(Syscall integerity checker_detector_init);
module_exit(Syscall integerity checker_detector_exit);
