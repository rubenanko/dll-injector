#include <utils/stdio-sec.h>

bool seek_checked(FILE *fp, long offset, long size) {
  if (offset < 0 || offset > size) {
    return false;
  }
  return fseek(fp, offset, SEEK_SET) == 0;
}
