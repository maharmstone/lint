#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include "../kernel/ioctls.h"

int main() {
    int fd, ret;

    fd = open("/dev/muwine", 0);
    if (fd < 0) {
        fprintf(stderr, "Couldn't open /dev/muwine: error %d\n", fd);
        return 1;
    }

    ret = ioctl(fd, MUWINE_IOCTL_INIT_REGISTRY);
    if (ret < 0) {
        fprintf(stderr, "MUWINE_IOCTL_INIT_REGISTRY: error %d\n", ret);
        close(fd);
        return 1;
    }

    printf("MUWINE_IOCTL_INIT_REGISTRY returned %d\n", ret);

    close(fd);

    return 0;
}
