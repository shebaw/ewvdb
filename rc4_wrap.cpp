#include "rc4.h"
#include "rc4_wrap.h"

void rc4_crypt(unsigned char *key, size_t key_size, const unsigned char *src,
	unsigned char *dest, size_t src_size)
{
	unsigned char sbox[0x100];
	rc4_ksched(key, key_size, sbox);
	rc4(sbox, src, dest, src_size);
}
