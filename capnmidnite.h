
#include "rc4.h"
#include "md5.h"

#define KB_SIZE 256

typedef struct
   {
   	RC4_KEY * Rc4KeyG1;
	MD5_CTX * ctx;
	unsigned char digeststr[16];
	unsigned char result[33];
	unsigned char hashx;
	unsigned char hashy;
	int	mode;
   } DECODER_RING;
