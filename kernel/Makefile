obj-m += muw.o
muw-objs += muwine.o reg.o sec.o file.o handle.o unixfs.o obj.o sect.o thread.o proc.o timer.o \
            event.o mutant.o semaphore.o

ccflags-y += -fshort-wchar

all:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
