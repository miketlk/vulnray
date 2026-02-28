#ifndef SCAN_SKIP_PROTOTYPES_H
#define SCAN_SKIP_PROTOTYPES_H

#include <stddef.h>

/*
 * Declaration-only prototypes used to verify function chunking skips
 * non-definition entries.
 */
int parse_user_record(const char *line, size_t line_len);
void sync_user_cache(const char *region, int force);

static int derive_user_token(
    const char *username,
    const unsigned char *salt,
    size_t salt_len,
    int rounds
);

#endif
