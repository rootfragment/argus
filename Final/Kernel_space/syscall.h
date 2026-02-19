#ifndef SYSCALL_H
#define SYSCALL_H

#include <linux/seq_file.h>

void syscall_list(struct seq_file *m);

#endif
