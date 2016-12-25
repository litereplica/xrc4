#include <memory.h>

#define SWAP(a, b) \
    temp = a;      \
    a = b;         \
    b = temp;

/* Retrieves a co-prime of 256 that is not equal to the last one used */
unsigned int xrc4_coprime(unsigned char in, unsigned int last_used) {
    unsigned int coprime;

    coprime = (((in & 1) ? in : in + 57) ^ 96) & 255;
    assert((coprime & 1) == 1);
    if (coprime == last_used) {
      coprime = (coprime + 2) & 255;  /* adds an even number so it remains odd */
    }

    return coprime;
}

/* KSA */
void xrc4_init(const unsigned char *key, unsigned int key_length, unsigned char *sbox) {
    unsigned int i=0, j=0, n, increment;
    unsigned char temp;

    increment = xrc4_coprime(key[0], 0);

    for (n = 0; n < 256; n++) {
        i = (i + increment) & 255;
        sbox[i] = n;
    }

    increment = xrc4_coprime(key[1 % key_length], increment);

    i = 0;
    for (n = 0; n < 3 * 256; n++) {
        i = (i + increment) & 255;
        j = (j + key[i % key_length] + sbox[i]) & 255;
        SWAP(sbox[i], sbox[j]);
    }

}

/* PRGA */
void xrc4_crypt(unsigned char *buf, unsigned int len, unsigned char *sbox,
                unsigned char *iv, unsigned int ivlen, unsigned int counter) {
    const unsigned int NUM_SWAPS = 256;
    unsigned int  i, j, n, increment;
    unsigned char s[256];
    unsigned char temp;

    /* state setup for the local sbox **********************************/

    /* copy the sbox with its original state derived only from the key */
    memcpy(s, sbox, 256);

    /* if no initialization vector is provided we use the current sbox */
    if (iv==0 || ivlen<=0) {
      /* it could use the original sbox, but in this case the reading of
      ** both memory buffers bellow can make it slower */
      iv = s;
      ivlen = 256;
    }

    /* get initial values for i and j from the counter */
    i = (counter & 0xff0000) >> 16;        // byte 3
    j = (counter & 0xff000000) >> 24;      // byte 4
    increment = xrc4_coprime(iv[0], 0);

    /* swap the sbox values using the IV and 2 bytes from the counter */
    for (n = 0; n < NUM_SWAPS; n++) {
      i = (i + increment) & 255;
      j = (j + iv[j % ivlen] + s[i]) & 255;
      SWAP(s[i], s[j]);
    }

    /* state setup for the encryption/decryption **********************/
    i = counter & 0xff;                    // byte 1
    j = (counter & 0xff00) >> 8;           // byte 2
    increment = xrc4_coprime(i, increment);

    /* encryption/decryption */
    for (n = 0; n < len; n++) {
      i = (i + increment) & 255;
      j = (j + s[i]) & 255;
      SWAP(s[i], s[j]);

      *buf ^= s[(s[i] + s[j]) & 255];
      buf++;
    }

}

/* PRGA - simpler and faster, but also weaker - uses a 32 bit nonce */
void xrc4_simple_crypt(unsigned char *buf, unsigned int len, unsigned char *s, unsigned int nonce) {
    unsigned int  n, i, j, increment1, increment2;
    unsigned char temp;

    /* state setup - 2^24 different keystreams (instead of 2^32) due to xrc4_coprime */
    i = nonce & 0xff;
    j = (nonce & 0xff00) >> 8;
    increment1 = xrc4_coprime( ((nonce >> 16) ^ (nonce >> 8)) & 0xff, 0);
    increment2 = xrc4_coprime( ((nonce >> 24) ^ nonce) & 0xff, increment1);

    /* encryption/decryption */
    for (n = 0; n < len; n++) {
      i = (i + increment1) & 255;
      j = (j + s[i] + increment2) & 255;
      SWAP(s[i], s[j]);

      *buf ^= s[(s[i] + s[j]) & 255];
      buf++;
    }
}
