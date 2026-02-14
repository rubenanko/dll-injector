#include <utils/log.h>

/**
 * hexdump - prints the content of a buffer in hexadecimal format
 *
 * @buffer: pointer to the buffer to be printed
 * @bufferSize: size of the buffer in bytes
 */
void hexdump(void *buffer, int bufferSize) {
  unsigned char *casted_buffer = buffer;
  for (int i = 0; i < bufferSize; i++) {
    printf("0x%02x ", *(casted_buffer++));

    // newline every 16 bytes
    if (((i + 1) % 16) == 0)
      printf("\n");
    else
      // tabulation between two QWORDs
      if (((i + 1) % 8) == 0)
        printf("\t");
  }

  printf("\n");
}
