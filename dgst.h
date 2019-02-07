
#ifndef DGST_H_
#define DGST_H_

#include <efi.h>

#define ERROR_MSG_LEN 80

extern int DGST_verifyAll(CHAR16 error[ERROR_MSG_LEN]);

#endif // DGST_H_
