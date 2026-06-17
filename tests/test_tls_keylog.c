/*
 * test_tls_keylog.c — verify NSS SSLKEYLOGFILE parser
 *
 * Constructs a synthetic keylog file, loads it via the TLS decrypt
 * processor, and verifies that all five record types are correctly
 * indexed by client_random.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "netpipe.h"
#include "../src/pipeline/np_pipeline.h"

/* Pull in the internal types so we can inspect the keylog table. */
#include "../src/processor/np_tls_decrypt.c"

static int tests_run = 0;
static int tests_passed = 0;

#define TEST(name) do { tests_run++; fprintf(stderr, "  [test] %s ... ", name); } while (0)
#define PASS()     do { tests_passed++; fprintf(stderr, "PASS\n"); } while (0)
#define FAIL(...) do { fprintf(stderr, "FAIL: " __VA_ARGS__); fprintf(stderr, "\n"); } while (0)

static void write_test_keylog(const char *path)
{
    FILE *fp = fopen(path, "w");
    if (!fp) { perror("fopen"); exit(1); }
    /* TLS 1.2 record. */
    fprintf(fp, "CLIENT_RANDOM ");
    for (int i = 0; i < 32; i++) fprintf(fp, "%02x", (uint8_t)i);
    fprintf(fp, " ");
    for (int i = 0; i < 48; i++) fprintf(fp, "%02x", (uint8_t)(0xa0 + i));
    fprintf(fp, "\n");
    /* TLS 1.3 client handshake secret. */
    fprintf(fp, "CLIENT_HANDSHAKE_TRAFFIC_SECRET ");
    for (int i = 0; i < 32; i++) fprintf(fp, "%02x", (uint8_t)(0x10 + i));
    fprintf(fp, " ");
    for (int i = 0; i < 32; i++) fprintf(fp, "%02x", (uint8_t)(0xb0 + i));
    fprintf(fp, "\n");
    /* TLS 1.3 server handshake secret. */
    fprintf(fp, "SERVER_HANDSHAKE_TRAFFIC_SECRET ");
    for (int i = 0; i < 32; i++) fprintf(fp, "%02x", (uint8_t)(0x10 + i));
    fprintf(fp, " ");
    for (int i = 0; i < 32; i++) fprintf(fp, "%02x", (uint8_t)(0xc0 + i));
    fprintf(fp, "\n");
    /* TLS 1.3 client app secret. */
    fprintf(fp, "CLIENT_TRAFFIC_SECRET_0 ");
    for (int i = 0; i < 32; i++) fprintf(fp, "%02x", (uint8_t)(0x10 + i));
    fprintf(fp, " ");
    for (int i = 0; i < 32; i++) fprintf(fp, "%02x", (uint8_t)(0xd0 + i));
    fprintf(fp, "\n");
    /* TLS 1.3 server app secret. */
    fprintf(fp, "SERVER_TRAFFIC_SECRET_0 ");
    for (int i = 0; i < 32; i++) fprintf(fp, "%02x", (uint8_t)(0x10 + i));
    fprintf(fp, " ");
    for (int i = 0; i < 32; i++) fprintf(fp, "%02x", (uint8_t)(0xe0 + i));
    fprintf(fp, "\n");
    /* Bogus line — should be skipped. */
    fprintf(fp, "GARBAGE_LINE foo bar\n");
    /* Empty line — should be skipped. */
    fprintf(fp, "\n");
    fclose(fp);
}

int main(void)
{
    np_init();

    const char *keylog_path = "/tmp/test_tls_keylog.txt";
    write_test_keylog(keylog_path);

    TEST("TLS decrypt processor can be created");
    np_processor_t *p = np_processor_tls_decrypt(keylog_path);
    if (p) PASS(); else { FAIL("processor is NULL"); return 1; }

    TEST("keylog loaded with 5 records");
    tls_decrypt_ctx_t *ctx = p->priv;
    if (ctx->keylog.nrecords == 5) PASS();
    else FAIL("nrecords=%d (expected 5)", ctx->keylog.nrecords);

    TEST("CLIENT_RANDOM (TLS 1.2) record is retrievable");
    {
        uint8_t cr[32];
        for (int i = 0; i < 32; i++) cr[i] = (uint8_t)i;
        const tls_keyrec_t *r = keylog_find(&ctx->keylog, cr, TLS_REC_CLIENT_RANDOM);
        if (r && r->secret_len == 48 && r->secret[0] == 0xa0) PASS();
        else FAIL("r=%p len=%zu", (const void*)r, r ? r->secret_len : 0);
    }

    TEST("CLIENT_HANDSHAKE_TRAFFIC_SECRET record is retrievable");
    {
        uint8_t cr[32];
        for (int i = 0; i < 32; i++) cr[i] = (uint8_t)(0x10 + i);
        const tls_keyrec_t *r = keylog_find(&ctx->keylog, cr, TLS_REC_C_HS_SECRET);
        if (r && r->secret_len == 32 && r->secret[0] == 0xb0) PASS();
        else FAIL("r=%p", (const void*)r);
    }

    TEST("CLIENT_TRAFFIC_SECRET_0 record is retrievable");
    {
        uint8_t cr[32];
        for (int i = 0; i < 32; i++) cr[i] = (uint8_t)(0x10 + i);
        const tls_keyrec_t *r = keylog_find(&ctx->keylog, cr, TLS_REC_C_APP_SECRET);
        if (r && r->secret[0] == 0xd0) PASS();
        else FAIL("r=%p", (const void*)r);
    }

    TEST("SERVER_TRAFFIC_SECRET_0 record is retrievable");
    {
        uint8_t cr[32];
        for (int i = 0; i < 32; i++) cr[i] = (uint8_t)(0x10 + i);
        const tls_keyrec_t *r = keylog_find(&ctx->keylog, cr, TLS_REC_S_APP_SECRET);
        if (r && r->secret[0] == 0xe0) PASS();
        else FAIL("r=%p", (const void*)r);
    }

    TEST("lookup of unknown client_random returns NULL");
    {
        uint8_t cr[32] = {0};  /* all zeros — not in keylog */
        const tls_keyrec_t *r = keylog_find(&ctx->keylog, cr, TLS_REC_CLIENT_RANDOM);
        if (r == NULL) PASS();
        else FAIL("expected NULL, got %p", (const void*)r);
    }

    /* Free the processor. */
    p->ops->free(p);
    np_cleanup();

    fprintf(stderr, "\n%d/%d tests passed\n", tests_passed, tests_run);
    return tests_passed == tests_run ? 0 : 1;
}
