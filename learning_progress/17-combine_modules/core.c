#include<linux/kernel.h>
#include<linux/module.h>
#include<linux/init.h>
#include "demo.h"

MODULE_LICENSE("GPL");

static int __init core_entry(void){
	pr_info("Core module initiated \n");
	part_1_fun();
	part_2_fun();
	part_3_fun();
	
	return 0;
}


static void __exit core_exit(void){
	pr_info("Exiting core module\n");
}

module_init(core_entry);
module_exit(core_exit);

