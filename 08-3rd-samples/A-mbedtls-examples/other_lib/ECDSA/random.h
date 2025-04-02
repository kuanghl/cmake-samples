#ifndef __RANDOM_H__
#define __RANDOM_H__

/* For uint32_t */
#include <stdint.h>
/* For size_t */
#include <stddef.h>

uint32_t arc4random(void);
void arc4random_buf(void *buf, size_t n);

#endif // !__RANDOM_H__
