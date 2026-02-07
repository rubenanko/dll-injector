#ifndef STDIO_SEC_H
#define STDIO_SEC_H 

#include <stdbool.h>
#include <stdio.h>

bool seek_checked(FILE *fp, long offset, long size);
#endif // !STDIO_SEC_H
