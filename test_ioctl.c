#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>

typedef uint64_t u64;
typedef uint16_t u16;

#define KBASE_IOCTL_TYPE    0x80
#define KBASE_IOCTL_VERSION_CHECK _IOWR(KBASE_IOCTL_TYPE, 52, struct kbase_ioctl_version_check)

struct kbase_ioctl_version_check { u16 major; u16 minor; };

int main() {
    int fd = open("/dev/mali0", O_RDWR);
    if (fd < 0) { perror("open"); return 1; }
    struct kbase_ioctl_version_check ver = {0};
    int ret = ioctl(fd, KBASE_IOCTL_VERSION_CHECK, &ver);
    printf("ioctl ret=%d, errno=%d, ver=%u.%u\n", ret, errno, ver.major, ver.minor);
    close(fd);
    return 0;
}
