#include <linux/kernel.h>
#include <linux/seq_file.h>
#include <linux/unistd.h>
#include <linux/kallsyms.h>

extern unsigned long *sys_call_table;
extern unsigned long *golden_sys_call_table;

void syscall_list(struct seq_file *m)
{
    int i;
    int tampered = 0;
    char sym_name[KSYM_NAME_LEN];
    char new_sym[KSYM_NAME_LEN];

    if (!golden_sys_call_table || !sys_call_table) {
        seq_printf(m, "Syscall tables not initialized.\n");
        return;
    }

    for (i = 0; i < NR_syscalls; i++) {
        if (sys_call_table[i] != golden_sys_call_table[i]) {
            tampered = 1;
            break;
        }
    }

    if (!tampered) {
        seq_printf(m, "0\n");
        return;
    }

    seq_printf(m, "-1\n");

    for (i = 0; i < NR_syscalls; i++) {
        if (sys_call_table[i] != golden_sys_call_table[i]) {
            memset(sym_name, 0, sizeof(sym_name));
            memset(new_sym, 0, sizeof(new_sym));
            sprint_symbol(sym_name, (unsigned long)golden_sys_call_table[i]);
            sprint_symbol(new_sym,(unsigned long)sys_call_table[i]);
            seq_printf(m, "%s | %s\n", sym_name, new_sym);
        }
    }
}
