/*i didn't how to do the errors so i just copied them from Claude, thanks Claude .
    */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include "../include/sha256.h"

#define PATH_MAX_LEN 4096
#define READ_BUF_SIZE 8192

static int hash_file(const char *filepath, char *out_hex, long *out_size) {
    FILE *fp = fopen(filepath, "rb");
    if (!fp) {
        return -1;
    }

    SHA256_CTX_LOCAL ctx;
    sha256_init(&ctx);

    unsigned char buf[READ_BUF_SIZE];
    size_t bytes_read;
    long total_size = 0;

    while ((bytes_read = fread(buf, 1, READ_BUF_SIZE, fp)) > 0) {
        sha256_update(&ctx, buf, bytes_read);
        total_size += (long)bytes_read;
    }

    if (ferror(fp)) {
        fclose(fp);
        return -1;
    }

    unsigned char digest[SHA256_BLOCK_SIZE];
    sha256_final(&ctx, digest);
    fclose(fp);

    for (int i = 0; i < SHA256_BLOCK_SIZE; i++) {
        sprintf(out_hex + (i * 2), "%02x", digest[i]);
    }

    out_hex[64] = '\0';
    *out_size = total_size;

    return 0;
}

static void walk_directory(const char *dirpath, FILE *out) {
    DIR *dir = opendir(dirpath);

    if (!dir) {
        fprintf(stderr, "Warning: could not open directory %s\n", dirpath);
        return;
    }

    struct dirent *entry;
    char full_path[PATH_MAX_LEN];

    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        int path_len = snprintf(
            full_path, sizeof(full_path),
            "%s/%s", dirpath, entry->d_name
        );

        if (path_len < 0 || path_len >= PATH_MAX_LEN) {
            fprintf(stderr, "Warning: path is too long\n");
            continue;
        }

        struct stat st;

        if (stat(full_path, &st) != 0) {
            continue;
        }

        if (S_ISDIR(st.st_mode)) {
            walk_directory(full_path, out);
        } else if (S_ISREG(st.st_mode)) {
            char hex_hash[65];
            long size;

            if (hash_file(full_path, hex_hash, &size) == 0) {
                fprintf(out, "%s,%s,%ld\n", full_path, hex_hash, size);
                printf("Hashed: %s\n", full_path);
            } else {
                fprintf(stderr, "Warning: could not read %s\n", full_path);
            }
        }
    }

    closedir(dir);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <file_or_directory> [output.csv]\n", argv[0]);
        return 1;
    }

    const char *target = argv[1];
    const char *output_path = argc >= 3 ? argv[2] : "hashes.csv";

    struct stat st;

    if (stat(target, &st) != 0) {
        fprintf(stderr, "Error: cannot access %s\n", target);
        return 1;
    }

    if (!S_ISDIR(st.st_mode) && !S_ISREG(st.st_mode)) {
        fprintf(stderr, "Error: target is not a regular file or directory\n");
        return 1;
    }

    FILE *out = fopen(output_path, "w");

    if (!out) {
        fprintf(stderr, "Error: could not open output file %s\n", output_path);
        return 1;
    }

    fprintf(out, "filepath,sha256_hash,size_bytes\n");

    if (S_ISDIR(st.st_mode)) {
        walk_directory(target, out);
    } else {
        char hex_hash[65];
        long size;

        if (hash_file(target, hex_hash, &size) == 0) {
            fprintf(out, "%s,%s,%ld\n", target, hex_hash, size);
            printf("Hashed: %s\n", target);
        } else {
            fprintf(stderr, "Error: could not read %s\n", target);
            fclose(out);
            return 1;
        }
    }

    fclose(out);
    printf("\nDone. Results written to %s\n", output_path);

    return 0;
}
