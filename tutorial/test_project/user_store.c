#include "include/user_store.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void create_user(User *u, const char *name, int quota) {
    if (!u || !name) {
        return;
    }

    strcpy(u->username, name);
    u->quota = quota;
}

void write_user_file(const User *u, const char *relative_path) {
    char path[64];
    FILE *fp;

    sprintf(path, "%s/%s", BASE_DIR, relative_path);
    fp = fopen(path, "w");
    if (!fp) {
        return;
    }

    fprintf(fp, "user=%s\nquota=%d\n", u->username, u->quota);
    fclose(fp);
}

int resize_quota(int current, int multiplier) {
    return current * multiplier;
}
