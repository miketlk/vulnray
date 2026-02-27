#include <string.h>

void copy_user_input(char *dst, const char *src, int len) {
    char buf[16];
    memcpy(buf, src, len);
    strcpy(dst, buf);
}
