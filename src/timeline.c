#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <time.h>

#define PATH_MAX_LEN 4096
#define MAX_ENTRIES 100000

typedef struct {
    char path[PATH_MAX_LEN];
    long long size;
    time_t atime;
    time_t mtime;
    time_t ctime;
} FileRecord;

static FileRecord *records;
static int record_count = 0;

static void format_time(time_t t, char *buf, size_t buflen) {
    struct tm *tm_info = localtime(&t);

    if (tm_info == NULL || strftime(buf, buflen, "%Y-%m-%d %H:%M:%S", tm_info) == 0) {
        snprintf(buf, buflen, "unknown");
    }
}

static int compare_by_mtime(const void *a, const void *b) {
    const FileRecord *fa = a;
    const FileRecord *fb = b;

    if (fa->mtime < fb->mtime) return -1;
    if (fa->mtime > fb->mtime) return 1;
    return 0;
}

static void walk_directory(const char *dirpath) {
    DIR *dir = opendir(dirpath);

    if (dir == NULL) {
        fprintf(stderr, "Warning: could not open directory %s\n", dirpath);
        return;
    }

    struct dirent *entry;
    char full_path[PATH_MAX_LEN];

    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        int len = snprintf(full_path, sizeof(full_path), "%s/%s", dirpath, entry->d_name);

        if (len < 0 || (size_t)len >= sizeof(full_path)) {
            continue;
        }

        struct stat st;

        if (lstat(full_path, &st) != 0) {
            continue;
        }

        if (S_ISDIR(st.st_mode)) {
            walk_directory(full_path);
        } else if (S_ISREG(st.st_mode)) {
            if (record_count >= MAX_ENTRIES) {
                fprintf(stderr, "Warning: maximum number of files reached\n");
                break;
            }

            FileRecord *rec = &records[record_count++];

            snprintf(rec->path, sizeof(rec->path), "%s", full_path);
            rec->size = (long long)st.st_size;
            rec->atime = st.st_atime;
            rec->mtime = st.st_mtime;
            rec->ctime = st.st_ctime;
        }
    }

    closedir(dir);
}

int main(int argc, char *argv[]) {
    if (argc < 2 || argc > 3) {
        fprintf(stderr, "Usage: %s <directory> [output.csv]\n", argv[0]);
        return 1;
    }

    const char *target = argv[1];
    const char *output_path = argc == 3 ? argv[2] : "timeline.csv";

    struct stat st;

    if (stat(target, &st) != 0 || !S_ISDIR(st.st_mode)) {
        fprintf(stderr, "Error: %s is not a valid directory\n", target);
        return 1;
    }

    records = malloc(sizeof(FileRecord) * MAX_ENTRIES);

    if (records == NULL) {
        fprintf(stderr, "Error: memory allocation failed\n");
        return 1;
    }

    printf("Scanning %s...\n", target);
    walk_directory(target);

    printf("Found %d files. Sorting by modification time...\n", record_count);
    qsort(records, record_count, sizeof(FileRecord), compare_by_mtime);

    FILE *out = fopen(output_path, "w");

    if (out == NULL) {
        fprintf(stderr, "Error: could not open output file %s\n", output_path);
        free(records);
        return 1;
    }

    fprintf(out, "path,size_bytes,accessed,modified,changed\n");

    char abuf[32], mbuf[32], cbuf[32];

    for (int i = 0; i < record_count; i++) {
        format_time(records[i].atime, abuf, sizeof(abuf));
        format_time(records[i].mtime, mbuf, sizeof(mbuf));
        format_time(records[i].ctime, cbuf, sizeof(cbuf));

        fprintf(out, "\"%s\",%lld,%s,%s,%s\n",
                records[i].path, records[i].size, abuf, mbuf, cbuf);
    }

    if (fclose(out) != 0) {
        fprintf(stderr, "Error: could not finish writing the output file\n");
        free(records);
        return 1;
    }

    free(records);

    printf("Done. Timeline written to %s\n", output_path);
    return 0;
}
