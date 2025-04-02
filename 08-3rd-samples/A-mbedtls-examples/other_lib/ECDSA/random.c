
#if __linux__
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>

#include "random.h"

uint32_t arc4random(void) 
{
    uint32_t value;

    int fd = open("/dev/urandom", O_RDONLY);
    if (fd == -1) {
        printf("open /dev/urandom failed.\n");
        return -1;
    } 
    ssize_t result = read(fd, &value, sizeof(uint32_t));
    if (result != sizeof(uint32_t)) {
        printf("read /dev/urandom failed.\n");
        close(fd);
        return -1;
    }
    close(fd);

    return value;
}

void arc4random_buf(void *buf, size_t n) {

    if (n == 0) {
        return;
    }

    int fd = open("/dev/urandom", O_RDONLY);
    if (fd == -1) {
        printf("open /dev/urandom failed.\n");
        return;
    } 
    ssize_t result = read(fd, buf, n);
    if (result != n) {
        printf("read /dev/urandom failed.\n");
        close(fd);
        return;
    }
    
    close(fd);
}

#endif