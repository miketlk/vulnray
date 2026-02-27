#ifndef USER_STORE_H
#define USER_STORE_H

#include <stddef.h>

#define USERNAME_MAX 32
#define BASE_DIR "./data"

typedef struct {
    char username[USERNAME_MAX];
    int quota;
} User;

void create_user(User *u, const char *name, int quota);
void write_user_file(const User *u, const char *relative_path);
int resize_quota(int current, int multiplier);

#endif
