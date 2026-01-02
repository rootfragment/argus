#include <linux/module.h>
#include <linux/types.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>

#define proc_name "controller"

static bool process_scan_enable = false;

static ssize_t detector_write(struct file *file,const char __user *user_buf,size_t count,loff_t *ppos){

	char buf[64];
	
	if(count > sizeof(buf) -1)
		return -EINVAL;
	
	if(copy_from_user(buf, user_buf, count))
		return -EFAULT;
		
	if (buf[count - 1] == '\n')
	   	buf[count - 1] = '\0';

	buf[count] = '\0';
	
	if(strncmp(buf, "start", 5) == 0){
		process_scan_enable = true;
		pr_info("Process scan flag set to : True\n");
		}
	else if (strncmp(buf,"stop", 4) == 0){
		process_scan_enable = false;
		pr_info("Process scan flag set to : False\n");
		}
	else{
		pr_info("Unknown command \n");
		}
	return count;
	}
	
static const struct proc_ops detector_ops = {
	.proc_write = detector_write,
};

static int __init detector_init(void)
{
	proc_create(proc_name,0666,NULL,&detector_ops);
	pr_info("Module loaded\n");
	return 0;}
	
static void __exit detector_exit(void){
	remove_proc_entry(proc_name,NULL);
	pr_info("Module unloaded\n");
}
module_init(detector_init);
module_exit(detector_exit);
MODULE_LICENSE("GPL");

