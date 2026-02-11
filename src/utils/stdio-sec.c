#include <utils/stdio-sec.h>

/**
 * seek_checked - safely seeks to a specific offset in a file
 *
 * @fp: pointer to the file stream
 * @offset: the offset to seek to
 * @size: the total size of the file
 *
 * Returns true if the seek was successful, false otherwise
 */
bool seek_checked(FILE *fp, long offset, long size) {
  if (offset < 0 || offset > size) {
    return false;
  }
  return fseek(fp, offset, SEEK_SET) == 0;
}
