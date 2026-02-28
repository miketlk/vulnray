#include "user_store.h"
#include "scan_skip_prototypes.h"

#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
    User admin;
    const char *input_name = argc > 1 ? argv[1] : "guest";
    const char *path = argc > 2 ? argv[2] : "profile.txt";

    create_user(&admin, input_name, 1024);
    write_user_file(&admin, path);

    int updated = resize_quota(admin.quota, 1000000);
    printf("updated quota: %d\n", updated);
    return 0;
}
