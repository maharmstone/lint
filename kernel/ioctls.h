#pragma once

#include <linux/ioctl.h>

#define MUWINE_IOCTL(num) _IOWR(0, num, 0) // FIXME - should be using proper major number

#define MUWINE_IOCTL_NTOPENKEY            MUWINE_IOCTL(0)
#define MUWINE_IOCTL_NTCLOSE              MUWINE_IOCTL(1)
#define MUWINE_IOCTL_NTENUMERATEKEY       MUWINE_IOCTL(2)
#define MUWINE_IOCTL_NTENUMERATEVALUEKEY  MUWINE_IOCTL(3)
#define MUWINE_IOCTL_NTQUERYVALUEKEY      MUWINE_IOCTL(4)
#define MUWINE_IOCTL_NTSETVALUEKEY        MUWINE_IOCTL(5)
#define MUWINE_IOCTL_NTDELETEVALUEKEY     MUWINE_IOCTL(6)
#define MUWINE_IOCTL_NTCREATEKEY          MUWINE_IOCTL(7)
#define MUWINE_IOCTL_NTDELETEKEY          MUWINE_IOCTL(8)
#define MUWINE_IOCTL_NTLOADKEY            MUWINE_IOCTL(9)
#define MUWINE_IOCTL_NTUNLOADKEY          MUWINE_IOCTL(10)
#define MUWINE_IOCTL_NTFLUSHKEY           MUWINE_IOCTL(11)
#define MUWINE_IOCTL_NTOPENKEYEX          MUWINE_IOCTL(12)
#define MUWINE_IOCTL_NTQUERYKEY           MUWINE_IOCTL(13)

#define MUWINE_IOCTL_MAX                  13
