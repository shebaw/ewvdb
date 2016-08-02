#ifndef _RC4_WRAP_H
#define _RC4_WRAP_H

#include <stdlib.h>

void rc4_crypt(unsigned char *key, size_t key_size, const unsigned char *src, 
	unsigned char *dest, size_t src_size);

#endif
