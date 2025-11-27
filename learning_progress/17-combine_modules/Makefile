obj-m += single_file.o

single_file-objs := core.o part_1.o part_2.o part_3.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

