obj-m += muw.o
muw-objs += muwine.o reg.o

ccflags-y += -fshort-wchar

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
