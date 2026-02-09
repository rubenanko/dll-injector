#include <utils/log.h>

void hexdump(unsigned char * buffer,int bufferSize)
{
    for(int i=0;i < bufferSize;i++)
    {
        printf("0x%02x ",*(buffer++));

        // newline every 16 bytes
        if(((i + 1) % 16) == 0)
            printf("\n");
        else
        // tabulation between two QWORDs
            if(((i + 1) % 8) == 0)
                printf("\t");
        
        }

        printf("\n");
    }