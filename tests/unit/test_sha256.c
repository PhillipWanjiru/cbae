/**
 * @file test_sha256.c
 * @brief SHA-256 against the FIPS 180-4 / NIST example vectors and against sha256sum(1).
 */
#include "platform/sha256.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define PASS(name) printf("  [PASS] %s\n", name)

static void hex_of(const void *data, size_t len, char out[65]) {
    uint8_t d[32];
    cbae_sha256(data, len, d);
    cbae_sha256_hex(d, out);
}

static void test_nist_vectors(void) {
    char h[65];
    hex_of("", 0, h);
    assert(strcmp(h, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") == 0);
    hex_of("abc", 3, h);
    assert(strcmp(h, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad") == 0);
    const char *m448 = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    hex_of(m448, strlen(m448), h);
    assert(strcmp(h, "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1") == 0);
    const char *m896 = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
    hex_of(m896, strlen(m896), h);
    assert(strcmp(h, "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1") == 0);
    hex_of(NULL, 0, h);
    assert(strcmp(h, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") == 0);   /* NULL with length 0 */
    PASS("FIPS 180-4 example messages (empty, abc, 448 bits, 896 bits)");
}

static void test_million_a_in_pieces(void) {
    static const size_t pieces[] = { 1, 7, 55, 56, 63, 64, 65, 1000, 4096 };
    uint8_t *a = malloc(1000000);
    assert(a);
    memset(a, 'a', 1000000);
    for (size_t i = 0; i < sizeof pieces / sizeof pieces[0]; i++) {
        cbae_sha256_t c;
        cbae_sha256_init(&c);
        for (size_t off = 0; off < 1000000; ) {
            size_t n = pieces[i] < 1000000 - off ? pieces[i] : 1000000 - off;
            cbae_sha256_update(&c, a + off, n);
            off += n;
        }
        uint8_t d[32];
        char h[65];
        cbae_sha256_final(&c, d);
        cbae_sha256_hex(d, h);
        assert(strcmp(h, "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0") == 0);
    }
    free(a);
    PASS("one million 'a' gives the NIST digest however the input is cut into pieces");
}

static void test_update_edge_cases(void) {
    /* empty updates in the middle of a message change nothing */
    cbae_sha256_t c;
    uint8_t d[32];
    char h[65];
    cbae_sha256_init(&c);
    cbae_sha256_update(&c, "a", 1);
    cbae_sha256_update(&c, NULL, 0);
    cbae_sha256_update(&c, "bc", 2);
    cbae_sha256_update(&c, "", 0);
    cbae_sha256_final(&c, d);
    cbae_sha256_hex(d, h);
    assert(strcmp(h, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad") == 0);
    /* final wipes the context: it is no longer the state of the message */
    uint8_t zero[sizeof c];
    memset(zero, 0, sizeof zero);
    assert(memcmp(&c, zero, sizeof c) == 0);
    PASS("empty updates are no-ops; final clears the context");
}

/* third-party oracle: sha256sum from coreutils over files of every length around the block boundaries */
static void test_against_sha256sum(void) {
    const int quick = getenv("CBAE_TEST_QUICK") != NULL;
    const size_t max_len = quick ? 70 : 300;
    char path[] = "/tmp/cbae_sha_XXXXXX";
    int fd = mkstemp(path);
    assert(fd >= 0);
    close(fd);
    unsigned checked = 0;
    uint8_t buf[512];
    for (size_t len = 0; len <= max_len; len++) {
        for (size_t i = 0; i < len; i++) buf[i] = (uint8_t)(i * 131u + len * 7u + 3u);
        FILE *f = fopen(path, "wb");
        assert(f);
        if (len) assert(fwrite(buf, 1, len, f) == len);
        fclose(f);
        char cmd[256];
        snprintf(cmd, sizeof cmd, "sha256sum '%s' 2>/dev/null", path);
        FILE *p = popen(cmd, "r");
        assert(p);
        char line[256] = "";
        const char *got = fgets(line, sizeof line, p);
        pclose(p);
        if (!got || strlen(line) < 64) { printf("  [SKIP] sha256sum is not available\n"); unlink(path); return; }
        line[64] = '\0';
        char mine[65];
        hex_of(buf, len, mine);
        if (strcmp(mine, line) != 0) { fprintf(stderr, "length %zu: mine %s, sha256sum %s\n", len, mine, line); assert(!"digest differs from sha256sum"); }
        checked++;
    }
    unlink(path);
    char msg[96];
    snprintf(msg, sizeof msg, "%u lengths (0..%zu) agree with sha256sum", checked, max_len);
    PASS(msg);
}

static void test_hex_format(void) {
    uint8_t d[32];
    for (int i = 0; i < 32; i++) d[i] = (uint8_t)(i * 17 + 1);
    char h[65];
    memset(h, 'Z', sizeof h);
    cbae_sha256_hex(d, h);
    assert(h[64] == '\0' && strlen(h) == 64);
    assert(strncmp(h, "0112233445566778", 16) == 0);          /* bytes 0x01 0x12 0x23 0x34 ... */
    for (int i = 0; i < 64; i++) assert((h[i] >= '0' && h[i] <= '9') || (h[i] >= 'a' && h[i] <= 'f'));
    PASS("hex is 64 lower-case digits and a NUL");
}

int main(void) {
    printf("=== test_sha256 ===\n");
    test_nist_vectors();
    test_million_a_in_pieces();
    test_update_edge_cases();
    test_against_sha256sum();
    test_hex_format();
    printf("All sha256 tests passed.\n");
    return 0;
}
