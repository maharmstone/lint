#pragma once

#include <linux/ioctl.h>

#define MUWINE_IOCTL(num) _IOWR(0, num, 0) // FIXME - should be using proper major number

#define MUWINE_IOCTL_INIT_REGISTRY        MUWINE_IOCTL(0)
#define MUWINE_IOCTL_NTOPENKEY            MUWINE_IOCTL(1)
#define MUWINE_IOCTL_NTCLOSE              MUWINE_IOCTL(2)
#define MUWINE_IOCTL_NTENUMERATEKEY       MUWINE_IOCTL(3)
#define MUWINE_IOCTL_NTENUMERATEVALUEKEY  MUWINE_IOCTL(4)

#define MUWINE_IOCTL_MAX                  4
