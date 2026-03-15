#include <utils/stdio-sec.h>

/**
 * seek_checked - safely seeks to a specific offset in a file
 *
 * @param fp pointer to the file stream
 * @param offset the offset to seek to
 * @param size the total size of the file
 *
 * Returns true if the seek was successful, false otherwise
 */
bool seek_checked(FILE *fp, long offset, long size) {
  if (offset < 0 || offset > size) {
    return false;
  }
  return fseek(fp, offset, SEEK_SET) == 0;
}
