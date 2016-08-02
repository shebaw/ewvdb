#ifndef RC4
#define RC4

void rc4(unsigned char sbox[0x100], const unsigned char *src, unsigned char *dest, unsigned long len);
void rc4_ksched(unsigned char *key, unsigned long keylen, unsigned char sbox[0x100]);
#endif