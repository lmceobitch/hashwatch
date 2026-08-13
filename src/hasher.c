/*
 * hasher.c - File integrity hasher for digital forensics toolkit
 *
 * Computes SHA-256 hashes of files to establish a "chain of custody"
 * baseline. Can hash a single file or recursively hash every file in
 * a directory, outputting results in a simple CSV format:
 *
 *      filepath,sha256_hash,size_bytes
 *
 * This CSV can later be compared against a fresh run to detect any
 * file that was added, removed, or modified.
 *
 * Usage:
 *   ./hasher <file_or_directory> [output.csv]
 *
 * Build:
 *   gcc -O2 -Wall -o hasher hasher.c
 *
 * Uses a self-contained SHA-256 implementation (include/sha256.h) so
 * the project has no external dependencies like libssl-dev.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include "../include/sha256.h"

#define PATH_MAX_LEN 4096
#define READ_BUF_SIZE 8192

/* Computes the SHA-256 hash of a file and writes it as a hex string
 * into out_hex (must be at least 65 bytes). Returns 0 on success. */
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

/* Recursively walks a directory, hashing every regular file found.
 * Writes one CSV line per file to the output stream. */
static void walk_directory(const char *dirpath, FILE *out) {
    DIR *dir = opendir(dirpath);
    if (!dir) {
        fprintf(stderr, "Warning: could not open directory %s\n", dirpath);
        return;
    }

    struct dirent *entry;
    char full_path[PATH_MAX_LEN];

    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        snprintf(full_path, sizeof(full_path), "%s/%s", dirpath, entry->d_name);

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
    const char *output_path = (argc >= 3) ? argv[2] : "hashes.csv";

    FILE *out = fopen(output_path, "w");
    if (!out) {
        fprintf(stderr, "Error: could not open output file %s\n", output_path);
        return 1;
    }

    fprintf(out, "filepath,sha256_hash,size_bytes\n");

    struct stat st;
    if (stat(target, &st) != 0) {
        fprintf(stderr, "Error: cannot access %s\n", target);
        fclose(out);
        return 1;
    }

    if (S_ISDIR(st.st_mode)) {
        walk_directory(target, out);
    } else if (S_ISREG(st.st_mode)) {
        char hex_hash[65];
        long size;
        if (hash_file(target, hex_hash, &size) == 0) {
            fprintf(out, "%s,%s,%ld\n", target, hex_hash, size);
            printf("Hashed: %s\n", target);
        } else {
            fprintf(stderr, "Error: could not read %s\n", target);
        }
    }

    fclose(out);
    printf("\nDone. Results written to %s\n", output_path);
    return 0;
}
