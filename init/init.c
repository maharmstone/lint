#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdint.h>
#include "../kernel/ioctls.h"

static int muwine_init_registry(int fd, const char* system) {
    uintptr_t args[] = {
        1,
        (uintptr_t)system
    };

    return ioctl(fd, MUWINE_IOCTL_INIT_REGISTRY, args);
}

int main() {
    int fd, ret;

    fd = open("/dev/muwine", 0);
    if (fd < 0) {
        fprintf(stderr, "Couldn't open /dev/muwine: error %d\n", fd);
        return 1;
    }

    ret = muwine_init_registry(fd, "/root/temp/init/SYSTEM");
    if (ret < 0) {
        fprintf(stderr, "muwine_init_registry: error %08x\n", ret);
        close(fd);
        return 1;
    }

    printf("muwine_init_registry returned %08x\n", ret);

    close(fd);

    return 0;
}
