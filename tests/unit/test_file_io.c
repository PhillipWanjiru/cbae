/**
 * @file test_file_io.c
 * @brief cbae_file_read and the path helpers (audit A-039).
 */
#include "platform/file_io.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define PASS(name) printf("  [PASS] %s\n", name)

static char g_dir[128];

static void path_in_dir(char *out, size_t n, const char *name) { snprintf(out, n, "%s/%s", g_dir, name); }

static void write_file(const char *path, const void *data, size_t len) {
    FILE *f = fopen(path, "wb");
    assert(f);
    if (len) assert(fwrite(data, 1, len, f) == len);
    assert(fclose(f) == 0);
}

static void test_read_back(void) {
    char p[192];
    path_in_dir(p, sizeof p, "plain.bin");
    uint8_t src[5000];
    for (size_t i = 0; i < sizeof src; i++) src[i] = (uint8_t)(i * 31u + 7u);
    write_file(p, src, sizeof src);
    cbae_file_data_t f = { (uint8_t *)1, 77 };       /* garbage in: must be overwritten */
    assert(cbae_file_read(p, &f) == CBAE_OK);
    assert(f.size == sizeof src && f.data && memcmp(f.data, src, sizeof src) == 0);
    cbae_file_release(&f);
    assert(f.data == NULL && f.size == 0);
    cbae_file_release(&f);                           /* twice is fine */
    cbae_file_release(NULL);
    PASS("a file reads back byte for byte into an exactly sized block; release is idempotent");
}

static void test_empty_file(void) {
    char p[192];
    path_in_dir(p, sizeof p, "empty.bin");
    write_file(p, NULL, 0);
    cbae_file_data_t f = { (uint8_t *)1, 77 };
    assert(cbae_file_read(p, &f) == CBAE_OK);
    assert(f.data == NULL && f.size == 0);
    cbae_file_release(&f);
    PASS("an empty file succeeds as {NULL, 0}");
}

static void test_errors(void) {
    char p[192];
    cbae_file_data_t f = { (uint8_t *)1, 77 };
    path_in_dir(p, sizeof p, "no_such_file");
    assert(cbae_file_read(p, &f) == CBAE_ERR_NOT_FOUND && f.data == NULL && f.size == 0);
    assert(strstr(cbae_last_error(), "no_such_file"));
    assert(cbae_file_read(g_dir, &f) == CBAE_ERR_INVALID);                      /* a directory */
    assert(cbae_file_read("/dev/null", &f) == CBAE_ERR_INVALID);                /* a device */
    assert(cbae_file_read(NULL, &f) == CBAE_ERR_INVALID);
    assert(cbae_file_read(p, NULL) == CBAE_ERR_INVALID);
    PASS("missing file, directory, device, NULL arguments: the right code, *out left empty");
}

static void alarm_handler(int sig) { (void)sig; _exit(99); }

static void test_fifo_does_not_hang(void) {
    char p[192];
    path_in_dir(p, sizeof p, "pipe");
    assert(mkfifo(p, 0600) == 0);
    signal(SIGALRM, alarm_handler);
    alarm(10);                                       /* opening a FIFO with no writer blocks forever unless refused */
    cbae_file_data_t f;
    assert(cbae_file_read(p, &f) == CBAE_ERR_INVALID);
    alarm(0);
    unlink(p);
    PASS("a FIFO is refused at once instead of blocking");
}

static void test_size_limit(void) {
    char p[192];
    path_in_dir(p, sizeof p, "sparse.bin");
    int fd = open(p, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    assert(fd >= 0);
    if (ftruncate(fd, (off_t)CBAE_FILE_MAX_BYTES + 1) != 0) { close(fd); unlink(p); printf("  [SKIP] cannot make a sparse file here\n"); return; }
    close(fd);
    cbae_file_data_t f;
    assert(cbae_file_read(p, &f) == CBAE_ERR_OVERFLOW && f.data == NULL && f.size == 0);
    unlink(p);
    PASS("a file over CBAE_FILE_MAX_BYTES is refused before anything is allocated");
}

static void test_path_helpers(void) {
    char p[192];
    path_in_dir(p, sizeof p, "plain.bin");
    assert(cbae_file_exists(p) && !cbae_file_exists("/nonexistent/zzz") && !cbae_file_exists(NULL));
    assert(strcmp(cbae_path_basename("/a/b/c.sys"), "c.sys") == 0);
    assert(strcmp(cbae_path_basename("c.sys"), "c.sys") == 0);
    assert(strcmp(cbae_path_basename("/a/b/"), "") == 0);
    assert(strcmp(cbae_path_basename(NULL), "") == 0);
    PASS("exists and basename");
}

int main(void) {
    printf("=== test_file_io ===\n");
    snprintf(g_dir, sizeof g_dir, "/tmp/cbae_fio_XXXXXX");
    assert(mkdtemp(g_dir));
    test_read_back();
    test_empty_file();
    test_errors();
    test_fifo_does_not_hang();
    test_size_limit();
    test_path_helpers();
    char cmd[200];
    snprintf(cmd, sizeof cmd, "rm -rf '%s'", g_dir);
    assert(system(cmd) == 0);
    printf("All file_io tests passed.\n");
    return 0;
}
