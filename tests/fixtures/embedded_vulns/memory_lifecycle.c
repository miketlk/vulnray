#include <stdlib.h>
#include <string.h>

struct session {
    char *token;
    int valid;
};

void insecure_session_cleanup(struct session *s) {
    if (s->token) {
        free(s->token);
    }
    if (s->valid) {
        free(s->token);
    }
    s->token = NULL;
}

int use_after_free_path(char *dst, const char *src) {
    char *tmp = (char *)malloc(16);
    if (!tmp) {
        return -1;
    }
    strcpy(tmp, src);
    free(tmp);
    if (dst) {
        dst[0] = tmp[0];
    }
    return 0;
}
