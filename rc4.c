/* Implemented from David Sterndark's Sept 14, 1994 email */

#include "rc4.h"

void
prep_key(unsigned char *key_data_ptr, int key_data_len, RC4_KEY *key)
{
        unsigned char swapByte;
        unsigned char index1;
        unsigned char index2;
        unsigned char* state;
        short counter;
        
	state = &key->state[0];
        for(counter = 0; counter < 256; counter++)              
        state[counter] = counter;               
        key->x = 0;     
        key->y = 0;     
        index1 = 0;     
        index2 = 0;             
        for(counter = 0; counter < 256; counter++)      
        {               
             index2 = (key_data_ptr[index1] + state[counter] + index2) % 256;                
             swapByte = state[counter];
             state[counter] = state[index2];
             state[index2] = swapByte;
             index1 = (index1 + 1) % key_data_len;  
        }       
}

void 
rc4(unsigned char *buffer_ptr, unsigned long buffer_len, RC4_KEY *key)
{ 
        unsigned char x;
        unsigned char y;
        unsigned char* state;
        unsigned char xorIndex;
	unsigned char swapByte;
        unsigned long counter;              
        
        x = key->x;
        y = key->y;

        state = &key->state[0];
        for(counter = 0; counter < buffer_len; counter ++)      
        {               
             x = (x + 1) % 256;
             y = (state[x] + y) % 256;
             swapByte = state[x];
             state[x] = state[y];
             state[y] = swapByte;
             xorIndex = (state[x] + state[y]) % 256;
             buffer_ptr[counter] ^= state[xorIndex];
         }
         key->x = x;
         key->y = y;
}
