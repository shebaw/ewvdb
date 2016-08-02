/*
 *File:        Crypto.c
 *Description: Needed to decrypt the database files (rc4 encryption)
 *Author:      x-n20
 *WebSite:     http://www.x-n2o.com
 *
*/

void rc4_ksched(unsigned char *key, unsigned long keylen, unsigned char sbox[0x100]) 
{
	unsigned long i, j;

	for(i = 0; i < 0x100; i++)
		sbox[i] = (unsigned char)i;

	for(j = i = 0; i < 0x100; i++) {
		unsigned char tmp;

		j = (j + sbox[i] + key[i % keylen]) & 0xff;
		tmp     = sbox[i];
		sbox[i] = sbox[j];
		sbox[j] = tmp;
	}
}

void rc4(unsigned char sbox[0x100], const unsigned char *src, unsigned char *dest, unsigned long len) 
{
	unsigned long i, j;

	i = j = 0;
	while(len--) {
		unsigned char tmp;

		i = (i + 1) & 0xff;
		j = (j + sbox[i]) & 0xff;

		tmp     = sbox[i];
		sbox[i] = sbox[j];
		sbox[j] = tmp;

		*dest++ = *src++ ^ sbox[(sbox[i] + sbox[j]) % 0xff];
	}
}

