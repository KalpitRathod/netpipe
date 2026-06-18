/*
 * np_tls_decrypt.c — TLS session decryption processor
 *
 * Implements NSS SSLKEYLOGFILE-based decryption of TLS 1.2 and 1.3
 * traffic using OpenSSL AEAD primitives (AES-GCM and ChaCha20-Poly1305).
 *
 * Architecture
 * ─────────────
 * 1. Key-log parser.  On construction, the processor loads the
 *    keylog file (one record per line) and builds a hash table of
 *    client-random → key-material records.  Records come in five
 *    flavours:
 *
 *        CLIENT_RANDOM <cr_hex> <ms_hex>                    (TLS 1.2)
 *        CLIENT_HANDSHAKE_TRAFFIC_SECRET <cr_hex> <sec_hex> (TLS 1.3 c→s hs)
 *        SERVER_HANDSHAKE_TRAFFIC_SECRET <cr_hex> <sec_hex> (TLS 1.3 s→c hs)
 *        CLIENT_TRAFFIC_SECRET_0 <cr_hex> <sec_hex>         (TLS 1.3 c→s app)
 *        SERVER_TRAFFIC_SECRET_0 <cr_hex> <sec_hex>         (TLS 1.3 s→c app)
 *
 * 2. Handshake tracker.  As TLS records flow through the pipeline,
 *    the processor watches for ClientHello and ServerHello records.
 *    From ClientHello it extracts the 32-byte client_random and
 *    associates it with the flow (5-tuple).  From ServerHello it
 *    extracts the cipher suite and the negotiated TLS version.
 *
 * 3. Per-flow session.  For each flow with key material, the
 *    processor maintains:
 *      • handshake keys (TLS 1.3 only) for decrypting handshake records
 *      • application traffic keys for decrypting application data
 *      • the 64-bit sequence number per direction (incremented per record)
 *
 * 4. Record decryption.  Each TLS record of type APPLICATION_DATA
 *    (23) is decrypted with the appropriate traffic key using
 *    EVP_DecryptInit_ex / EVP_DecryptUpdate / EVP_DecryptFinal_ex.
 *    The 16-byte AEAD auth tag is verified; on failure the record
 *    is dropped and a counter incremented.
 *
 * Decrypted plaintext replaces the original TLS layer in the
 * packet's np_layer_t stack: the bytes pointed to by layer->data
 * become a freshly-allocated heap buffer owned by the packet.
 *
 * LIMITATIONS
 * ───────────
 *  • TLS 1.3 0-RTT early data is not decrypted.
 *  • TLS 1.3 key updates are not yet supported.
 *  • Cipher suites that use CBC mode (e.g. AES_128_CBC_SHA256) are
 *    not supported — GCM and ChaCha20-Poly1305 cover >95% of
 *    modern TLS traffic.
 *  • Pre-shared key (PSK) modes require the SSLKEYLOGFILE entries
 *    to be present; we do not derive PSK binders ourselves.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <time.h>
#include <pthread.h>

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/kdf.h>
#include <openssl/sha.h>
#include <openssl/crypto.h>   /* Bug TLS-DEC-06 fix: OPENSSL_cleanse */

#include "netpipe.h"
#include "../pipeline/np_pipeline.h"
#include "../log/np_log.h"
#include "../packet/np_packet.h"

/* ------------------------------------------------------------------ */
/*  Constants                                                           */
/* ------------------------------------------------------------------ */

#define TLS_KEYLOG_BUCKETS   1024
#define TLS_FLOW_BUCKETS     1024
#define TLS_MAX_CLIENT_RANDOM 32
#define TLS_MAX_SECRET        64
#define TLS_MAX_RECORD        16384
#define TLS_GCM_TAG_LEN       16
#define TLS_HDR_LEN           5
#define TLS_CH_RANDOM_OFFSET  6    /* ClientHello: type(1)+len(3)+version(2)+random(32) */
#define TLS_SH_RANDOM_OFFSET  6    /* ServerHello: same layout */
#define TLS_SH_CIPHER_OFFSET  44   /* type+len+ver+random(32)+session_id_len(1)+session_id(32)+cipher(2) */
#define TLS_HS_LEN            4    /* type(1)+len(3) */

#define TLS_CT_CHANGE_CIPHER  20
#define TLS_CT_ALERT          21
#define TLS_CT_HANDSHAKE      22
#define TLS_CT_APPLICATION    23

#define TLS_HS_CLIENT_HELLO   1
#define TLS_HS_SERVER_HELLO   2

/* ------------------------------------------------------------------ */
/*  Key-log records                                                     */
/* ------------------------------------------------------------------ */

typedef enum {
    TLS_REC_CLIENT_RANDOM = 0,     /* TLS 1.2 master secret   */
    TLS_REC_C_HS_SECRET,           /* TLS 1.3 client handshake */
    TLS_REC_S_HS_SECRET,           /* TLS 1.3 server handshake */
    TLS_REC_C_APP_SECRET,          /* TLS 1.3 client app      */
    TLS_REC_S_APP_SECRET,          /* TLS 1.3 server app      */
} tls_rec_type_t;

typedef struct tls_keyrec {
    struct tls_keyrec *next;
    tls_rec_type_t     type;
    uint8_t            client_random[TLS_MAX_CLIENT_RANDOM];
    uint8_t            secret[TLS_MAX_SECRET];
    size_t             secret_len;
} tls_keyrec_t;

typedef struct {
    tls_keyrec_t *buckets[TLS_KEYLOG_BUCKETS];
    int           nrecords;
} tls_keylog_t;

/* ------------------------------------------------------------------ */
/*  Per-flow session                                                    */
/* ------------------------------------------------------------------ */

typedef enum {
    TLS_VERSION_UNKNOWN = 0,
    TLS_VERSION_1_2     = 0x0303,
    TLS_VERSION_1_3     = 0x0304,
} tls_version_t;

typedef struct tls_aead_key {
    uint8_t  key[32];        /* max 32 bytes (AES-256)                  */
    size_t   key_len;
    uint8_t  iv[12];          /* 12 bytes for TLS 1.3 GCM & ChaCha20     */
    /* TLS 1.2 GCM uses a 4-byte implicit IV from the key_block, plus an
     * 8-byte explicit nonce carried in each record.  We store the 4-byte
     * implicit IV here and combine it with the per-record explicit nonce
     * at decrypt time.  is_tls12 selects which path aead_decrypt_* uses. */
    uint8_t  implicit_iv[4];
    bool     is_tls12;
    EVP_CIPHER_CTX *ctx;      /* ready-to-use decrypt context            */
    bool     ready;
} tls_aead_key_t;

typedef struct tls_flow {
    struct tls_flow *next;
    uint32_t         flow_id;     /* canonical, direction-agnostic      */
    uint8_t          client_random[TLS_MAX_CLIENT_RANDOM];
    uint8_t          server_random[TLS_MAX_CLIENT_RANDOM];  /* TLS 1.2 */
    tls_version_t    version;
    uint16_t         cipher_suite;
    bool             have_client_random;
    bool             have_server_random;
    bool             have_cipher;

    /* Client endpoint (IP+port) recorded from the ClientHello, so we
     * can determine direction by comparing against the current packet's
     * source — much more reliable than the port-magnitude heuristic
     * that fails for high server ports (8443, 8080) and for ephemeral-
     * vs-ephemeral peer-to-peer traffic.  Bug 9.3. */
    uint8_t          client_ip[16];
    uint16_t         client_port;
    uint8_t          client_ip_ver;   /* 4 or 6 */
    bool             have_client_endpoint;

    /* Per-direction application-traffic keys (derived lazily). */
    tls_aead_key_t   c_app_key;   /* client → server */
    tls_aead_key_t   s_app_key;   /* server → client */

    /* Per-direction handshake-traffic keys (TLS 1.3 only — needed to
     * decrypt the encrypted handshake records that come after ServerHello:
     * EncryptedExtensions, Certificate, CertificateVerify, Finished.
     * These records have outer content_type=23 (APPLICATION_DATA) but
     * are encrypted with the handshake traffic secret, not the app one. */
    tls_aead_key_t   c_hs_key;    /* client → server (client Finished) */
    tls_aead_key_t   s_hs_key;    /* server → client (EncryptedExtensions...Finished) */

    /* Per-direction record sequence numbers (one per key per direction). */
    uint64_t         c_app_seq;
    uint64_t         s_app_seq;
    uint64_t         c_hs_seq;
    uint64_t         s_hs_seq;

    /* TLS 1.2 ChangeCipherSpec tracking.  After CCS, all records in that
     * direction are encrypted (including the Finished handshake message,
     * which has outer type=22 but is ciphertext).  The Finished message
     * consumes sequence number 0, so the first ApplicationData record
     * after CCS uses seq=1.  Without tracking CCS, we'd try seq=0 for
     * ApplicationData and the AEAD auth would fail.  Bug found during
     * TLS 1.2 implementation. */
    bool             c_ccs_seen;   /* client→saw CCS */
    bool             s_ccs_seen;   /* server→saw CCS */

    /* Decryption stats. */
    uint64_t         stat_records_total;
    uint64_t         stat_records_decrypted;
    uint64_t         stat_records_failed;

    struct timespec  last_seen;
} tls_flow_t;

typedef struct {
    tls_keylog_t  keylog;
    tls_flow_t   *flows[TLS_FLOW_BUCKETS];
    int           nflows;
    pthread_mutex_t lock;   /* Bug M5 fix: protect flows[] + nflows */

    /* Global stats. */
    uint64_t      stat_total_packets;
    uint64_t      stat_total_decrypted;
} tls_decrypt_ctx_t;

/* ------------------------------------------------------------------ */
/*  Hex parsing                                                          */
/* ------------------------------------------------------------------ */

static int hex_val(int c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* Parse a hex string of length hex_len into out (which must hold hex_len/2 bytes).
 * Returns the number of bytes written, or -1 on error. */
static int parse_hex(const char *hex, size_t hex_len, uint8_t *out, size_t out_max)
{
    if (hex_len % 2 != 0) return -1;
    size_t n = hex_len / 2;
    if (n > out_max) return -1;
    for (size_t i = 0; i < n; i++) {
        int hi = hex_val(hex[i * 2]);
        int lo = hex_val(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) return -1;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return (int)n;
}

/* ------------------------------------------------------------------ */
/*  Key-log parser                                                      */
/* ------------------------------------------------------------------ */

static uint32_t hash_cr(const uint8_t *cr)
{
    uint32_t h = 5381u;
    for (int i = 0; i < TLS_MAX_CLIENT_RANDOM; i += 4) {
        uint32_t w;
        memcpy(&w, cr + i, 4);
        h = ((h << 5) + h) ^ w;
    }
    return h;
}

static void keylog_add(tls_keylog_t *kl, tls_rec_type_t type,
                       const uint8_t *cr, const uint8_t *sec, size_t sec_len)
{
    tls_keyrec_t *r = calloc(1, sizeof(*r));
    if (!r) return;
    r->type = type;
    memcpy(r->client_random, cr, TLS_MAX_CLIENT_RANDOM);
    if (sec_len > TLS_MAX_SECRET) sec_len = TLS_MAX_SECRET;
    memcpy(r->secret, sec, sec_len);
    r->secret_len = sec_len;
    uint32_t h = hash_cr(cr) & (TLS_KEYLOG_BUCKETS - 1);
    r->next = kl->buckets[h];
    kl->buckets[h] = r;
    kl->nrecords++;
}

/* Returns the first keyrec matching the given client_random and type, or NULL. */
static const tls_keyrec_t *keylog_find(const tls_keylog_t *kl,
                                        const uint8_t *cr,
                                        tls_rec_type_t type)
{
    uint32_t h = hash_cr(cr) & (TLS_KEYLOG_BUCKETS - 1);
    for (const tls_keyrec_t *r = kl->buckets[h]; r; r = r->next) {
        if (r->type == type && memcmp(r->client_random, cr, TLS_MAX_CLIENT_RANDOM) == 0) {
            return r;
        }
    }
    return NULL;
}

static void keylog_free(tls_keylog_t *kl)
{
    for (int i = 0; i < TLS_KEYLOG_BUCKETS; i++) {
        tls_keyrec_t *r = kl->buckets[i];
        while (r) {
            tls_keyrec_t *next = r->next;
            /* Bug TLS-DEC-06 fix: wipe the secret before freeing so it
             * doesn't linger in freed heap memory.  The client_random
             * is not secret so we don't bother cleansing it. */
            OPENSSL_cleanse(r->secret, sizeof(r->secret));
            free(r);
            r = next;
        }
        kl->buckets[i] = NULL;
    }
    kl->nrecords = 0;
}

/* Parse one key-log line and add to kl.  Returns true on success. */
static bool keylog_parse_line(tls_keylog_t *kl, char *line)
{
    /* Strip trailing newline. */
    size_t len = strlen(line);
    while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r')) {
        line[--len] = '\0';
    }
    if (len == 0) return false;

    /* Split into label + cr_hex + sec_hex. */
    char *sp1 = strchr(line, ' ');
    if (!sp1) return false;
    char *sp2 = strchr(sp1 + 1, ' ');
    if (!sp2) return false;

    *sp1 = '\0'; *sp2 = '\0';
    const char *label = line;
    const char *cr_hex = sp1 + 1;
    const char *sec_hex = sp2 + 1;

    tls_rec_type_t type;
    if      (strcmp(label, "CLIENT_RANDOM") == 0)               type = TLS_REC_CLIENT_RANDOM;
    else if (strcmp(label, "CLIENT_HANDSHAKE_TRAFFIC_SECRET") == 0) type = TLS_REC_C_HS_SECRET;
    else if (strcmp(label, "SERVER_HANDSHAKE_TRAFFIC_SECRET") == 0) type = TLS_REC_S_HS_SECRET;
    else if (strcmp(label, "CLIENT_TRAFFIC_SECRET_0") == 0)     type = TLS_REC_C_APP_SECRET;
    else if (strcmp(label, "SERVER_TRAFFIC_SECRET_0") == 0)     type = TLS_REC_S_APP_SECRET;
    else return false;

    uint8_t cr[TLS_MAX_CLIENT_RANDOM];
    uint8_t sec[TLS_MAX_SECRET];
    int cr_n = parse_hex(cr_hex, strlen(cr_hex), cr, sizeof(cr));
    if (cr_n != TLS_MAX_CLIENT_RANDOM) return false;
    int sec_n = parse_hex(sec_hex, strlen(sec_hex), sec, sizeof(sec));
    if (sec_n <= 0) return false;

    keylog_add(kl, type, cr, sec, (size_t)sec_n);
    return true;
}

static void keylog_load(tls_keylog_t *kl, const char *path)
{
    FILE *fp = fopen(path, "r");
    if (!fp) {
        NP_LOG_ERROR("tls_decrypt: cannot open keylog '%s'", path);
        return;
    }
    char line[1024];
    int n = 0;
    while (fgets(line, sizeof(line), fp)) {
        if (keylog_parse_line(kl, line)) n++;
    }
    fclose(fp);
    NP_LOG_INFO("tls_decrypt: loaded %d keylog records from %s", n, path);
}

/* ------------------------------------------------------------------ */
/*  HKDF-Expand-Label (RFC 8446 §7.1)                                   */
/* ------------------------------------------------------------------ */

/*
 * HKDF-Expand-Label(Secret, Label, Context, Length) =
 *   HKDF-Expand(Secret, HkdfLabel, Length)
 * where HkdfLabel = struct {
 *   uint16 length = Length;
 *   opaque label<7..255> = "tls13 " + Label;
 *   opaque context<0..255> = Context;
 * }
 */
static bool hkdf_expand_label(const uint8_t *secret, size_t secret_len,
                               const char *label,
                               const uint8_t *context, size_t context_len,
                               uint8_t *out, size_t out_len,
                               const EVP_MD *md)
{
    uint8_t info[256];
    size_t label_len = strlen(label);
    size_t total_label_len = 6 + label_len;  /* "tls13 " prefix */

    if (total_label_len > 255) return false;
    if (context_len > 255) return false;
    if (2 + 1 + total_label_len + 1 + context_len > sizeof(info)) return false;

    size_t off = 0;
    /* length (uint16 big-endian) */
    info[off++] = (uint8_t)(out_len >> 8);
    info[off++] = (uint8_t)(out_len & 0xff);
    /* label length + label */
    info[off++] = (uint8_t)total_label_len;
    memcpy(info + off, "tls13 ", 6); off += 6;
    memcpy(info + off, label, label_len); off += label_len;
    /* context length + context */
    info[off++] = (uint8_t)context_len;
    if (context_len > 0) {
        memcpy(info + off, context, context_len);
        off += context_len;
    }

    /* HKDF-Expand (RFC 5869 §2.3) using the hash function specified by
     * the cipher suite (SHA-256 for AES-128-GCM/ChaCha20, SHA-384 for
     * AES-256-GCM in TLS 1.3).
     *
     *   T(0) = empty
     *   T(i) = HMAC(secret, T(i-1) | info | byte(i))
     *   OKM  = T(1) | T(2) | ...  (truncated to out_len)
     *
     * IMPORTANT: the counter byte MUST be appended even in the single-
     * block case — earlier versions forgot it and silently produced
     * wrong keys, causing every AEAD auth to fail. */
    uint8_t t[EVP_MAX_MD_SIZE];
    size_t t_len = 0;
    size_t done = 0;
    uint8_t counter = 1;
    while (done < out_len) {
        EVP_PKEY *pk = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, secret, (int)secret_len);
        if (!pk) return false;
        EVP_MD_CTX *m = EVP_MD_CTX_new();
        if (!m) { EVP_PKEY_free(pk); return false; }
        if (EVP_DigestSignInit(m, NULL, md, NULL, pk) != 1) {
            EVP_MD_CTX_free(m); EVP_PKEY_free(pk); return false;
        }
        if (t_len > 0) {
            if (EVP_DigestSignUpdate(m, t, t_len) != 1) {
                EVP_MD_CTX_free(m); EVP_PKEY_free(pk); return false;
            }
        }
        if (EVP_DigestSignUpdate(m, info, off) != 1) {
            EVP_MD_CTX_free(m); EVP_PKEY_free(pk); return false;
        }
        if (EVP_DigestSignUpdate(m, &counter, 1) != 1) {
            EVP_MD_CTX_free(m); EVP_PKEY_free(pk); return false;
        }
        size_t sigl = sizeof(t);
        if (EVP_DigestSignFinal(m, t, &sigl) != 1) {
            EVP_MD_CTX_free(m); EVP_PKEY_free(pk); return false;
        }
        t_len = sigl;
        size_t copy = (out_len - done < t_len) ? (out_len - done) : t_len;
        memcpy(out + done, t, copy);
        done += copy;
        counter++;
        EVP_MD_CTX_free(m);
        EVP_PKEY_free(pk);
    }
    return true;
}

/* ------------------------------------------------------------------ */
/*  TLS 1.3 traffic-key derivation                                      */
/* ------------------------------------------------------------------ */

static bool derive_tls13_traffic_key(const uint8_t *secret, size_t secret_len,
                                      uint8_t *key_out, size_t key_len,
                                      const EVP_MD *md)
{
    return hkdf_expand_label(secret, secret_len, "key",
                              NULL, 0, key_out, key_len, md);
}

static bool derive_tls13_traffic_iv(const uint8_t *secret, size_t secret_len,
                                     uint8_t *iv_out, const EVP_MD *md)
{
    return hkdf_expand_label(secret, secret_len, "iv",
                              NULL, 0, iv_out, 12, md);
}

/* ------------------------------------------------------------------ */
/*  AEAD context setup                                                  */
/* ------------------------------------------------------------------ */

/*
 * Returns the EVP cipher for a given suite, AND the matching HKDF hash
 * function.  In TLS 1.3 the hash is part of the cipher suite name:
 *   0x1301 TLS_AES_128_GCM_SHA256       → SHA-256
 *   0x1302 TLS_AES_256_GCM_SHA384       → SHA-384
 *   0x1303 TLS_CHACHA20_POLY1305_SHA256 → SHA-256
 *
 * TLS 1.2 doesn't use HKDF-Expand-Label (it uses the TLS PRF), so for
 * TLS 1.2 suites the md output is unused (we set it to SHA-256 for
 * safety, but the TLS 1.2 path doesn't reach the HKDF code).
 */
static const EVP_CIPHER *cipher_for_suite(uint16_t suite,
                                            size_t *key_len_out,
                                            const EVP_MD **md_out)
{
    switch (suite) {
    /* TLS 1.3 suites */
    case 0x1301:  /* TLS_AES_128_GCM_SHA256 */
        *key_len_out = 16;  *md_out = EVP_sha256(); return EVP_aes_128_gcm();
    case 0x1302:  /* TLS_AES_256_GCM_SHA384 */
        *key_len_out = 32;  *md_out = EVP_sha384(); return EVP_aes_256_gcm();
    case 0x1303:  /* TLS_CHACHA20_POLY1305_SHA256 */
        *key_len_out = 32;  *md_out = EVP_sha256(); return EVP_chacha20_poly1305();
    /* TLS 1.2 GCM suites (md_out is informational only) */
    case 0xc02f:  /* ECDHE_RSA_WITH_AES_128_GCM_SHA256 */
    case 0xc02b:  /* ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 */
    case 0x009c:  /* RSA_WITH_AES_128_GCM_SHA256 */
        *key_len_out = 16;  *md_out = EVP_sha256(); return EVP_aes_128_gcm();
    case 0xc030:  /* ECDHE_RSA_WITH_AES_256_GCM_SHA384 */
    case 0xc02c:  /* ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 */
    case 0x009d:  /* RSA_WITH_AES_256_GCM_SHA384 */
        *key_len_out = 32;  *md_out = EVP_sha384(); return EVP_aes_256_gcm();
    case 0xcca8:  /* ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 */
    case 0xcca9:  /* ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 */
        *key_len_out = 32;  *md_out = EVP_sha256(); return EVP_chacha20_poly1305();
    default:
        return NULL;
    }
}

static bool aead_key_setup(tls_aead_key_t *k,
                            const uint8_t *secret, size_t secret_len,
                            uint16_t cipher_suite)
{
    size_t key_len = 0;
    const EVP_MD *md = NULL;
    const EVP_CIPHER *cipher = cipher_for_suite(cipher_suite, &key_len, &md);
    if (!cipher) {
        NP_LOG_DEBUG("tls_decrypt: unsupported cipher suite 0x%04x", cipher_suite);
        return false;
    }
    if (key_len > sizeof(k->key)) return false;

    if (!derive_tls13_traffic_key(secret, secret_len, k->key, key_len, md)) {
        NP_LOG_DEBUG("tls_decrypt: key derivation failed");
        return false;
    }
    k->key_len = key_len;

    if (!derive_tls13_traffic_iv(secret, secret_len, k->iv, md)) {
        NP_LOG_DEBUG("tls_decrypt: IV derivation failed");
        return false;
    }

    k->ctx = EVP_CIPHER_CTX_new();
    if (!k->ctx) return false;

    /* Initialise the cipher + key + IV length on the context.  Without
     * this, EVP_DecryptInit_ex(ctx, NULL, NULL, NULL, nonce) in
     * aead_decrypt() returns 0 (failure) because no cipher is associated
     * with the context. */
    if (EVP_DecryptInit_ex(k->ctx, cipher, NULL, k->key, k->iv) != 1) {
        NP_LOG_DEBUG("tls_decrypt: EVP_DecryptInit_ex failed for suite 0x%04x",
                     cipher_suite);
        EVP_CIPHER_CTX_free(k->ctx);
        k->ctx = NULL;
        return false;
    }
    /* GCM default IV length is 12, but set it explicitly for safety. */
    if (EVP_CIPHER_CTX_ctrl(k->ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) != 1) {
        EVP_CIPHER_CTX_free(k->ctx);
        k->ctx = NULL;
        return false;
    }

    k->ready = true;
    return true;
}

static void aead_key_free(tls_aead_key_t *k)
{
    if (k->ctx) {
        EVP_CIPHER_CTX_free(k->ctx);
        k->ctx = NULL;
    }
    /* Bug TLS-DEC-06 fix: wipe the key + IV material before marking
     * the slot un-ready.  Without this, the key bytes linger in heap
     * memory until the slot is reused or the process exits. */
    OPENSSL_cleanse(k->key, sizeof(k->key));
    OPENSSL_cleanse(k->iv, sizeof(k->iv));
    OPENSSL_cleanse(k->implicit_iv, sizeof(k->implicit_iv));
    k->ready = false;
}

/* ------------------------------------------------------------------ */
/*  Per-record nonce (RFC 8446 §5.3): XOR IV with sequence number      */
/* ------------------------------------------------------------------ */

static void build_nonce(uint8_t *nonce, const uint8_t *iv, uint64_t seq)
{
    memcpy(nonce, iv, 12);
    for (int i = 0; i < 8; i++) {
        nonce[11 - i] ^= (uint8_t)((seq >> (i * 8)) & 0xff);
    }
}

/* ------------------------------------------------------------------ */
/*  AEAD decrypt one record                                             */
/* ------------------------------------------------------------------ */

static bool aead_decrypt(const tls_aead_key_t *k, uint64_t seq,
                          uint8_t content_type,
                          const uint8_t *ciphertext, size_t ct_len,
                          uint8_t *plaintext_out, size_t *pt_len_out)
{
    (void)content_type;  /* AAD uses the outer TLS record type, which
                          * we already pass via the AAD buffer. */
    if (!k->ready || ct_len < TLS_GCM_TAG_LEN) return false;

    size_t pt_len = ct_len - TLS_GCM_TAG_LEN;
    if (pt_len > TLS_MAX_RECORD) return false;

    uint8_t nonce[12];
    build_nonce(nonce, k->iv, seq);

    /* AAD = TLS record header: type(1) + legacy_version(2) + length(2). */
    uint8_t aad[5];
    aad[0] = content_type;
    aad[1] = 0x03;  /* legacy_record_version high byte */
    aad[2] = 0x03;  /* legacy_record_version low byte  */
    aad[3] = (uint8_t)(ct_len >> 8);
    aad[4] = (uint8_t)(ct_len & 0xff);

    if (EVP_DecryptInit_ex(k->ctx, NULL, NULL, NULL, nonce) != 1) return false;
    int outlen = 0;
    if (EVP_DecryptUpdate(k->ctx, NULL, &outlen, aad, sizeof(aad)) != 1) return false;
    if (EVP_DecryptUpdate(k->ctx, plaintext_out, &outlen, ciphertext, (int)pt_len) != 1) return false;
    int total = outlen;
    if (EVP_CIPHER_CTX_ctrl(k->ctx, EVP_CTRL_GCM_SET_TAG, TLS_GCM_TAG_LEN,
                             (void *)(ciphertext + pt_len)) != 1) return false;
    if (EVP_DecryptFinal_ex(k->ctx, plaintext_out + outlen, &outlen) != 1) {
        return false;  /* auth tag mismatch */
    }
    total += outlen;
    *pt_len_out = (size_t)total;
    return true;
}

/* ------------------------------------------------------------------ */
/*  TLS 1.2 PRF (RFC 5246 §5)                                           */
/*                                                                      */
/*  PRF(secret, label, seed) = P_hash(secret, label + seed)             */
/*  P_hash(secret, seed) = HMAC_hash(secret, A(1)+seed) ||              */
/*                          HMAC_hash(secret, A(2)+seed) || …           */
/*  A(0) = seed,  A(i) = HMAC_hash(secret, A(i-1))                      */
/* ------------------------------------------------------------------ */

static bool tls12_prf(const uint8_t *secret, size_t secret_len,
                       const char *label,
                       const uint8_t *seed, size_t seed_len,
                       uint8_t *out, size_t out_len,
                       const EVP_MD *md)
{
    /* Build label+seed once (P_hash input). */
    size_t label_len = strlen(label);
    size_t ls_len = label_len + seed_len;
    uint8_t *ls = malloc(ls_len);
    if (!ls) return false;
    memcpy(ls, label, label_len);
    memcpy(ls + label_len, seed, seed_len);

    /* A(0) = label+seed; A(i) = HMAC(secret, A(i-1)). */
    uint8_t a[EVP_MAX_MD_SIZE];
    unsigned int a_len = 0;

    /* Iteration: produce HMAC(secret, A(i) + ls) blocks until out_len filled. */
    size_t done = 0;
    int iter = 0;
    while (done < out_len) {
        /* Compute A(i) = HMAC(secret, A(i-1)).  For i==0, A(0) = ls. */
        if (iter == 0) {
            /* A(1) = HMAC(secret, A(0)) = HMAC(secret, ls).  But the spec
             * defines A(0) = seed (which we treat as ls here, since the
             * PRF's "seed" parameter already includes the label).
             * P_hash first block = HMAC(secret, A(1) + ls) where A(1)
             * itself = HMAC(secret, A(0)) = HMAC(secret, ls).  So we
             * compute A(1) first, then the first P_hash block. */
            unsigned int al = 0;
            if (!HMAC(md, secret, (int)secret_len, ls, ls_len, a, &al)) {
                free(ls); return false;
            }
            a_len = al;
        } else {
            /* A(i) = HMAC(secret, A(i-1)). */
            uint8_t new_a[EVP_MAX_MD_SIZE];
            unsigned int new_al = 0;
            if (!HMAC(md, secret, (int)secret_len, a, a_len, new_a, &new_al)) {
                free(ls); return false;
            }
            memcpy(a, new_a, new_al);
            a_len = new_al;
        }

        /* Block = HMAC(secret, A(i) + ls). */
        uint8_t block[EVP_MAX_MD_SIZE];
        unsigned int block_len = 0;
        /* Manually concatenate A(i) + ls into a temp buffer. */
        size_t buf_len = a_len + ls_len;
        uint8_t *buf = malloc(buf_len);
        if (!buf) { free(ls); return false; }
        memcpy(buf, a, a_len);
        memcpy(buf + a_len, ls, ls_len);
        if (!HMAC(md, secret, (int)secret_len, buf, buf_len, block, &block_len)) {
            free(buf); free(ls); return false;
        }
        free(buf);

        /* Copy block to output, truncated if we're near the end. */
        size_t copy = (out_len - done < block_len) ? (out_len - done) : block_len;
        memcpy(out + done, block, copy);
        done += copy;
        iter++;
    }

    /* Zero out sensitive buffers. */
    OPENSSL_cleanse(a, sizeof(a));
    OPENSSL_cleanse(ls, ls_len);
    free(ls);
    return true;
}

/* ------------------------------------------------------------------ */
/*  TLS 1.2 AEAD decrypt (RFC 5288 §3 + RFC 5116)                       */
/*                                                                      */
/*  Each TLS 1.2 GCM record carries an 8-byte EXPLICIT nonce in the     */
/*  fragment, prepended to the ciphertext.  The full 12-byte nonce is:  */
/*      implicit_iv (4 bytes from key_block) || explicit_nonce (8)      */
/*  The AAD is 13 bytes:                                                */
/*      seq_num (8, big-endian) || content_type (1) ||                  */
/*      version (2: 0x03 0x03) || plaintext_length (2, big-endian)      */
/*  Note: TLS 1.2 AAD uses the PLAINTEXT length, not the ciphertext     */
/*  length.  This differs from TLS 1.3.                                 */
/* ------------------------------------------------------------------ */

static bool aead_decrypt_tls12(const tls_aead_key_t *k,
                                 uint64_t seq,
                                 uint8_t content_type,
                                 const uint8_t *rec_frag, size_t frag_len,
                                 uint8_t *plaintext_out, size_t *pt_len_out)
{
    if (!k->ready || !k->is_tls12) return false;
    /* TLS 1.2 GCM fragment = explicit_nonce(8) + ciphertext + tag(16).
     * Need at least 8 + 16 = 24 bytes. */
    if (frag_len < 8 + TLS_GCM_TAG_LEN) return false;

    const uint8_t *explicit_nonce = rec_frag;
    const uint8_t *ciphertext     = rec_frag + 8;
    size_t ct_len = frag_len - 8 - TLS_GCM_TAG_LEN;
    if (ct_len > TLS_MAX_RECORD) return false;
    const uint8_t *tag = rec_frag + 8 + ct_len;

    /* Build the 12-byte nonce: implicit (4) || explicit (8). */
    uint8_t nonce[12];
    memcpy(nonce, k->implicit_iv, 4);
    memcpy(nonce + 4, explicit_nonce, 8);

    /* AAD = seq(8) || type(1) || version(2) || plaintext_len(2). */
    uint8_t aad[13];
    for (int i = 0; i < 8; i++) {
        aad[i] = (uint8_t)((seq >> (56 - i * 8)) & 0xff);
    }
    aad[8]  = content_type;
    aad[9]  = 0x03;  /* TLS 1.2 version major-minor: 0x0303 */
    aad[10] = 0x03;
    aad[11] = (uint8_t)(ct_len >> 8);
    aad[12] = (uint8_t)(ct_len & 0xff);

    if (EVP_DecryptInit_ex(k->ctx, NULL, NULL, NULL, nonce) != 1) return false;
    int outlen = 0;
    if (EVP_DecryptUpdate(k->ctx, NULL, &outlen, aad, sizeof(aad)) != 1) return false;
    if (ct_len > 0) {
        if (EVP_DecryptUpdate(k->ctx, plaintext_out, &outlen, ciphertext, (int)ct_len) != 1) return false;
    } else {
        outlen = 0;
    }
    int total = outlen;
    if (EVP_CIPHER_CTX_ctrl(k->ctx, EVP_CTRL_GCM_SET_TAG, TLS_GCM_TAG_LEN,
                             (void *)tag) != 1) return false;
    if (EVP_DecryptFinal_ex(k->ctx, plaintext_out + outlen, &outlen) != 1) {
        return false;  /* auth tag mismatch */
    }
    total += outlen;
    *pt_len_out = (size_t)total;
    return true;
}

/* ------------------------------------------------------------------ */
/*  TLS 1.2 key-block derivation (RFC 5246 §6.3 + RFC 5288 §3)          */
/*                                                                      */
/*  key_block = PRF(master_secret, "key expansion",                     */
/*                  server_random || client_random,                     */
/*                  2 * key_len + 2 * 4)                                */
/*                                                                      */
/*  Layout (in order):                                                  */
/*    client_write_key  (key_len bytes)                                 */
/*    server_write_key  (key_len bytes)                                 */
/*    client_write_IV   (4 bytes — implicit IV)                         */
/*    server_write_IV   (4 bytes — implicit IV)                         */
/*                                                                      */
/*  Note: TLS 1.2 GCM does NOT include fixed IVs in the key_block       */
/*  for non-AEAD ciphers (CBC) — only the AEAD form uses 4-byte         */
/*  implicit IVs.  We do not support CBC.                              */
/* ------------------------------------------------------------------ */

static bool aead_key_setup_tls12(tls_aead_key_t *k,
                                   const uint8_t *master_secret, size_t ms_len,
                                   const uint8_t *server_random,
                                   const uint8_t *client_random,
                                   uint16_t cipher_suite,
                                   bool is_client_write)
{
    size_t key_len = 0;
    const EVP_MD *md = NULL;
    const EVP_CIPHER *cipher = cipher_for_suite(cipher_suite, &key_len, &md);
    if (!cipher || !md) {
        NP_LOG_DEBUG("tls_decrypt: TLS 1.2 unsupported cipher suite 0x%04x", cipher_suite);
        return false;
    }

    /* key_block = 2*key_len + 2*4 = 2*key_len + 8 bytes. */
    size_t kb_len = 2 * key_len + 8;
    uint8_t *key_block = malloc(kb_len);
    if (!key_block) return false;

    /* seed = server_random || client_random (note the order — RFC 5246
     * §6.3 is explicit about this). */
    uint8_t seed[64];
    memcpy(seed, server_random, 32);
    memcpy(seed + 32, client_random, 32);

    if (!tls12_prf(master_secret, ms_len, "key expansion",
                    seed, 64, key_block, kb_len, md)) {
        NP_LOG_DEBUG("tls_decrypt: TLS 1.2 PRF failed");
        free(key_block);
        return false;
    }

    /* Slice the key_block. */
    const uint8_t *client_write_key = key_block;
    const uint8_t *server_write_key = key_block + key_len;
    const uint8_t *client_write_iv  = key_block + 2 * key_len;
    const uint8_t *server_write_iv  = key_block + 2 * key_len + 4;

    const uint8_t *my_key = is_client_write ? client_write_key : server_write_key;
    const uint8_t *my_iv  = is_client_write ? client_write_iv  : server_write_iv;

    if (key_len > sizeof(k->key)) { free(key_block); return false; }
    memcpy(k->key, my_key, key_len);
    k->key_len = key_len;
    memcpy(k->implicit_iv, my_iv, 4);
    k->is_tls12 = true;

    k->ctx = EVP_CIPHER_CTX_new();
    if (!k->ctx) { free(key_block); return false; }

    /* Initialise cipher + key (IV is per-record, set at decrypt time). */
    if (EVP_DecryptInit_ex(k->ctx, cipher, NULL, k->key, NULL) != 1) {
        NP_LOG_DEBUG("tls_decrypt: TLS 1.2 EVP_DecryptInit_ex failed");
        EVP_CIPHER_CTX_free(k->ctx);
        k->ctx = NULL;
        free(key_block);
        return false;
    }
    if (EVP_CIPHER_CTX_ctrl(k->ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) != 1) {
        EVP_CIPHER_CTX_free(k->ctx);
        k->ctx = NULL;
        free(key_block);
        return false;
    }

    /* Scrub the key_block — it contains sensitive key material. */
    OPENSSL_cleanse(key_block, kb_len);
    free(key_block);

    k->ready = true;
    return true;
}

/* ------------------------------------------------------------------ */
/*  Flow tracking                                                       */
/* ------------------------------------------------------------------ */

/*
 * Compute a direction-agnostic flow key from a packet's 4-tuple.
 *
 * The demux layer hashes (src,dst) in a direction-sensitive way, so the
 * ClientHello (c→s) and ServerHello (s→c) end up with different flow_ids.
 * For TLS decryption both directions belong to the SAME connection and
 * share the same keys, so we compute a canonical key here by sorting the
 * endpoints (smaller IP+port first, larger second) before hashing.
 *
 * For IPv6 the same logic applies — we sort the 16-byte addresses.
 */
static uint32_t canonical_flow_key(const np_packet_t *pkt)
{
    if (!pkt->net || !pkt->transport) return pkt->flow_id;

    /* Extract endpoints. */
    uint8_t  ip_a[16], ip_b[16];
    uint16_t port_a = 0, port_b = 0;
    bool is_v6 = false;

    if (pkt->net->proto == NP_PROTO_IP4 && pkt->net->len >= 20) {
        memcpy(ip_a, pkt->net->data + 12, 4);
        memset(ip_a + 4, 0, 12);
        memcpy(ip_b, pkt->net->data + 16, 4);
        memset(ip_b + 4, 0, 12);
    } else if (pkt->net->proto == NP_PROTO_IP6 && pkt->net->len >= 40) {
        memcpy(ip_a, pkt->net->data + 8, 16);
        memcpy(ip_b, pkt->net->data + 24, 16);
        is_v6 = true;
    } else {
        return pkt->flow_id;
    }

    if (pkt->transport->proto == NP_PROTO_TCP && pkt->transport->len >= 4) {
        memcpy(&port_a, pkt->transport->data,     2);  port_a = ntohs(port_a);
        memcpy(&port_b, pkt->transport->data + 2, 2);  port_b = ntohs(port_b);
    } else if (pkt->transport->proto == NP_PROTO_UDP && pkt->transport->len >= 4) {
        memcpy(&port_a, pkt->transport->data,     2);  port_a = ntohs(port_a);
        memcpy(&port_b, pkt->transport->data + 2, 2);  port_b = ntohs(port_b);
    }

    /* Canonicalise: ensure (lo_ip, lo_port) < (hi_ip, hi_port) lexicographically. */
    int cmp = memcmp(ip_a, ip_b, 16);
    bool swap;
    if (cmp == 0) swap = (port_b < port_a);
    else          swap = (cmp > 0);
    if (swap) {
        uint8_t tmp_ip[16]; memcpy(tmp_ip, ip_a, 16); memcpy(ip_a, ip_b, 16); memcpy(ip_b, tmp_ip, 16);
        uint16_t tmp_p = port_a; port_a = port_b; port_b = tmp_p;
    }

    /* Hash. */
    uint32_t h = 5381u;
    for (int i = 0; i < 16; i += 4) {
        uint32_t w; memcpy(&w, ip_a + i, 4); h = ((h << 5) + h) ^ w;
    }
    for (int i = 0; i < 16; i += 4) {
        uint32_t w; memcpy(&w, ip_b + i, 4); h = ((h << 5) + h) ^ w;
    }
    h = ((h << 5) + h) ^ (((uint32_t)port_a << 16) | port_b);
    h ^= is_v6 ? 0x6 : 0x4;
    return h;
}

static tls_flow_t *flow_lookup_or_create(tls_decrypt_ctx_t *ctx, uint32_t flow_id)
{
    /* Bug M5 fix: take the context lock so two threads processing
     * packets on the same flow cannot both miss the lookup and insert
     * duplicate flow entries.  The lock is held briefly — just the
     * hash walk + (maybe) a calloc + link. */
    uint32_t h = flow_id & (TLS_FLOW_BUCKETS - 1);
    pthread_mutex_lock(&ctx->lock);
    tls_flow_t *f = ctx->flows[h];
    while (f) {
        if (f->flow_id == flow_id) {
            pthread_mutex_unlock(&ctx->lock);
            return f;
        }
        f = f->next;
    }
    f = calloc(1, sizeof(*f));
    if (!f) {
        pthread_mutex_unlock(&ctx->lock);
        return NULL;
    }
    f->flow_id = flow_id;
    f->next = ctx->flows[h];
    ctx->flows[h] = f;
    ctx->nflows++;
    pthread_mutex_unlock(&ctx->lock);
    return f;
}

static void flow_free_chain(tls_decrypt_ctx_t *ctx)
{
    for (int i = 0; i < TLS_FLOW_BUCKETS; i++) {
        tls_flow_t *f = ctx->flows[i];
        while (f) {
            tls_flow_t *next = f->next;
            aead_key_free(&f->c_app_key);
            aead_key_free(&f->s_app_key);
            aead_key_free(&f->c_hs_key);
            aead_key_free(&f->s_hs_key);
            free(f);
            f = next;
        }
        ctx->flows[i] = NULL;
    }
    ctx->nflows = 0;
}

/* ------------------------------------------------------------------ */
/*  TLS record parsing                                                  */
/* ------------------------------------------------------------------ */

/* Extract client_random from a ClientHello record (TLS 1.2 or 1.3).
 * record points at the start of the TLS record (type+version+length+fragment). */
static bool extract_client_random(const uint8_t *record, size_t len,
                                   uint8_t *cr_out)
{
    /* record[0]=type, [1..2]=version, [3..4]=length, [5..]=fragment. */
    if (len < TLS_HDR_LEN + TLS_CH_RANDOM_OFFSET + 32) return false;
    /* Verify it's a Handshake record. */
    if (record[0] != TLS_CT_HANDSHAKE) return false;
    /* Inside the fragment: handshake type (1) + length (3) + version (2) + random (32). */
    const uint8_t *frag = record + TLS_HDR_LEN;
    if (frag[0] != TLS_HS_CLIENT_HELLO) return false;
    memcpy(cr_out, frag + TLS_CH_RANDOM_OFFSET, 32);
    return true;
}

/* Extract cipher suite + server_random from a ServerHello record.
 *
 * The ServerHello fragment layout is:
 *   type(1) + len(3) + version(2) + random(32) +
 *   session_id_len(1) + session_id(0..32) + cipher(2) + ...
 *
 * For TLS 1.2 we need server_random to drive the key-derivation PRF
 * (RFC 5246 §6.3 — seed = server_random || client_random).  Without it,
 * we cannot derive the key_block and TLS 1.2 GCM decryption is
 * impossible.  This was Bug 9.1 in the audit.
 */
static bool extract_server_hello(const uint8_t *record, size_t len,
                                  uint16_t *cipher_out,
                                  tls_version_t *version_out,
                                  uint8_t *server_random_out)
{
    if (len < TLS_HDR_LEN + 2) return false;
    if (record[0] != TLS_CT_HANDSHAKE) return false;
    const uint8_t *frag = record + TLS_HDR_LEN;
    if (frag[0] != TLS_HS_SERVER_HELLO) return false;
    /* frag layout: type(1) + len(3) + version(2) + random(32) +
     *              session_id_len(1) + session_id(0..32) + cipher(2) + ... */
    if (len < TLS_HDR_LEN + 4 + 2 + 32 + 1) return false;
    /* Extract the 32-byte server_random at frag offset 6 (right after
     * type(1)+len(3)+version(2)). */
    if (server_random_out) {
        memcpy(server_random_out, frag + 6, 32);
    }
    size_t sid_off = TLS_HDR_LEN + 4 + 2 + 32;
    uint8_t sid_len = frag[sid_off - TLS_HDR_LEN];
    /* Bug TLS-DEC-03 fix: validate sid_len.  RFC 5246 §7.4.1.2 limits
     * the session_id to 32 bytes.  A malformed or attacker-crafted
     * ServerHello with sid_len = 255 would cause us to read the
     * cipher-suite bytes from the wrong offset (inside extension data
     * rather than right after the session_id), producing a bogus
     * cipher suite and silently failing every subsequent AEAD auth. */
    if (sid_len > 32) {
        NP_LOG_DEBUG("tls_decrypt: ServerHello sid_len=%u > 32, rejecting", sid_len);
        return false;
    }
    size_t cipher_off = sid_off + 1 + sid_len;
    if (len < cipher_off + 2) return false;
    uint16_t cipher = ((uint16_t)frag[cipher_off - TLS_HDR_LEN] << 8) |
                       frag[cipher_off - TLS_HDR_LEN + 1];
    *cipher_out = cipher;
    /* TLS 1.3 suites are in the 0x13xx range. */
    if ((cipher & 0xff00) == 0x1300) *version_out = TLS_VERSION_1_3;
    else                              *version_out = TLS_VERSION_1_2;
    return true;
}

/* ------------------------------------------------------------------ */
/*  Try to derive per-direction traffic keys for a flow                 */
/* ------------------------------------------------------------------ */

static void flow_maybe_derive_keys(tls_decrypt_ctx_t *ctx, tls_flow_t *f)
{
    if (!f->have_client_random || !f->have_cipher) return;

    /* For TLS 1.3, the SSLKEYLOGFILE contains:
     *   - CLIENT_HANDSHAKE_TRAFFIC_SECRET / SERVER_HANDSHAKE_TRAFFIC_SECRET
     *     (used to decrypt the encrypted handshake records: EncryptedExtensions,
     *      Certificate, CertificateVerify, Finished)
     *   - CLIENT_TRAFFIC_SECRET_0 / SERVER_TRAFFIC_SECRET_0
     *     (used to decrypt the application-data records that follow the
     *      server's Finished message)
     * Each secret is the direct input to HKDF-Expand-Label("key"/"iv"). */
    if (f->version == TLS_VERSION_1_3) {
        if (!f->c_hs_key.ready) {
            const tls_keyrec_t *r = keylog_find(&ctx->keylog, f->client_random,
                                                  TLS_REC_C_HS_SECRET);
            if (r) aead_key_setup(&f->c_hs_key, r->secret, r->secret_len, f->cipher_suite);
        }
        if (!f->s_hs_key.ready) {
            const tls_keyrec_t *r = keylog_find(&ctx->keylog, f->client_random,
                                                  TLS_REC_S_HS_SECRET);
            if (r) aead_key_setup(&f->s_hs_key, r->secret, r->secret_len, f->cipher_suite);
        }
        if (!f->c_app_key.ready) {
            const tls_keyrec_t *r = keylog_find(&ctx->keylog, f->client_random,
                                                  TLS_REC_C_APP_SECRET);
            if (r) aead_key_setup(&f->c_app_key, r->secret, r->secret_len, f->cipher_suite);
        }
        if (!f->s_app_key.ready) {
            const tls_keyrec_t *r = keylog_find(&ctx->keylog, f->client_random,
                                                  TLS_REC_S_APP_SECRET);
            if (r) aead_key_setup(&f->s_app_key, r->secret, r->secret_len, f->cipher_suite);
        }
    } else if (f->version == TLS_VERSION_1_2) {
        /* For TLS 1.2, CLIENT_RANDOM maps to the master secret.  We
         * derive per-direction write keys + implicit IVs via the TLS 1.2
         * PRF (RFC 5246 §6.3) using the seed = server_random ||
         * client_random.  Bug 9.1 from the audit: this was previously
         * a no-op stub. */
        if (!f->have_server_random) {
            /* Can't derive keys without server_random — wait for the
             * ServerHello to be processed. */
            return;
        }
        const tls_keyrec_t *r = keylog_find(&ctx->keylog, f->client_random,
                                              TLS_REC_CLIENT_RANDOM);
        if (!r) {
            NP_LOG_DEBUG("tls_decrypt: TLS 1.2 no CLIENT_RANDOM keylog record for flow 0x%08x",
                         f->flow_id);
            return;
        }
        if (!f->c_app_key.ready) {
            if (!aead_key_setup_tls12(&f->c_app_key, r->secret, r->secret_len,
                                       f->server_random, f->client_random,
                                       f->cipher_suite, /*is_client_write=*/true)) {
                NP_LOG_DEBUG("tls_decrypt: TLS 1.2 client key setup failed");
            }
        }
        if (!f->s_app_key.ready) {
            if (!aead_key_setup_tls12(&f->s_app_key, r->secret, r->secret_len,
                                       f->server_random, f->client_random,
                                       f->cipher_suite, /*is_client_write=*/false)) {
                NP_LOG_DEBUG("tls_decrypt: TLS 1.2 server key setup failed");
            }
        }
    }
}

/* ------------------------------------------------------------------ */
/*  Main processor                                                      */
/* ------------------------------------------------------------------ */

static np_err_t tls_process(np_processor_t *p, np_packet_t *pkt)
{
    tls_decrypt_ctx_t *ctx = p->priv;
    if (!ctx || !pkt->transport || !pkt->app) return NP_OK;
    if (pkt->app->proto != NP_PROTO_TLS) return NP_OK;

    ctx->stat_total_packets++;

    /* Determine flow direction (client→server or server→client).
     *
     * IMPORTANT: we use a CANONICAL, direction-agnostic flow key here —
     * NOT pkt->flow_id directly.  The demux's flow_id is direction-
     * sensitive, which would put the ClientHello (c→s) and ServerHello
     * (s→c) in different flow entries and prevent key association.  By
     * canonicalising the 4-tuple (sorting the two endpoints) both
     * directions map to the same flow entry. */
    uint32_t canon_key = canonical_flow_key(pkt);
    tls_flow_t *f = flow_lookup_or_create(ctx, canon_key);
    if (!f) return NP_ERR_NOMEM;
    clock_gettime(CLOCK_MONOTONIC, &f->last_seen);

    /* A single TCP segment may carry multiple TLS records (e.g. the
     * server's first flight: ServerHello + several encrypted handshake
     * records all in one segment).  Walk through every record in the
     * TLS layer so we don't miss any.
     *
     * Bug H9 fix: prefer pkt->stream_data (the reassembled TCP stream)
     * over pkt->app->data (the per-packet view).  When a TLS record
     * spans multiple TCP segments (e.g. the server's Certificate flight,
     * often 3-10 KB), pkt->app->data only sees the first fragment and
     * the record-walk loop bails out on the truncated-record check.
     * Using stream_data lets us decrypt records that crossed segment
     * boundaries — which is the whole point of doing reassembly. */
    const uint8_t *buf     = NULL;
    size_t         buf_len = 0;
    bool used_stream = false;
    if (pkt->stream_data && pkt->stream_len > 0) {
        buf     = pkt->stream_data;
        buf_len = pkt->stream_len;
        used_stream = true;
    } else if (pkt->app && pkt->app->data && pkt->app->len > 0) {
        buf     = pkt->app->data;
        buf_len = pkt->app->len;
    } else {
        /* No data to decrypt — nothing to do. */
        return NP_OK;
    }
    size_t         offset  = 0;

    /* Choose direction.
     *
     * Bug 9.3: the old port-magnitude heuristic
     *   `(sp > 1024 && dp < 1024) || (sp > dp)`
     * failed for high server ports (8443, 8080), peer-to-peer ephemeral-
     * vs-ephemeral traffic, and TLS 1.2 (which only tries one key per
     * direction with no fallback).  We now record the client endpoint
     * from the ClientHello and compare the current packet's source
     * against it.  Fall back to the heuristic only if we somehow never
     * saw a ClientHello (mid-stream capture). */
    bool is_client_to_server = false;
    uint16_t sp = 0, dp = 0;
    if (pkt->transport->proto == NP_PROTO_TCP && pkt->transport->len >= 4) {
        memcpy(&sp, pkt->transport->data, 2);
        memcpy(&dp, pkt->transport->data + 2, 2);
        sp = ntohs(sp); dp = ntohs(dp);
    }
    if (f->have_client_endpoint) {
        /* Compare current packet's source IP+port against the stored
         * client endpoint.  This is the gold-standard direction test. */
        bool src_is_client = false;
        if (pkt->net && pkt->net->proto == NP_PROTO_IP4 && pkt->net->len >= 20 &&
            f->client_ip_ver == 4) {
            uint8_t src_ip[4];
            memcpy(src_ip, pkt->net->data + 12, 4);
            if (memcmp(src_ip, f->client_ip, 4) == 0 && sp == f->client_port) {
                src_is_client = true;
            }
        } else if (pkt->net && pkt->net->proto == NP_PROTO_IP6 && pkt->net->len >= 40 &&
                   f->client_ip_ver == 6) {
            const uint8_t *src_ip6 = pkt->net->data + 8;
            if (memcmp(src_ip6, f->client_ip, 16) == 0 && sp == f->client_port) {
                src_is_client = true;
            }
        }
        is_client_to_server = src_is_client;
    } else {
        /* Fallback heuristic. */
        is_client_to_server = (sp > 1024 && dp < 1024) || (sp > dp);
    }

    /* Reusable plaintext buffer for the loop. */
    uint8_t *plaintext = malloc(TLS_MAX_RECORD);
    if (!plaintext) return NP_ERR_NOMEM;

    /* Accumulate decrypted plaintext across all records in this packet
     * so downstream sees the full application-layer view. */
    uint8_t *accumulated = NULL;
    size_t   accumulated_len = 0;

    while (offset + TLS_HDR_LEN <= buf_len) {
        const uint8_t *rec     = buf + offset;
        size_t         rec_len = buf_len - offset;
        uint8_t        ct      = rec[0];
        uint16_t       rlen    = ((uint16_t)rec[3] << 8) | rec[4];
        size_t         this_rec_total = (size_t)TLS_HDR_LEN + rlen;
        if (this_rec_total > rec_len) break;  /* truncated */
        /* Restrict rec_len to this single record for sub-callers. */
        rec_len = this_rec_total;

        /* ---- ChangeCipherSpec tracking (TLS 1.2) ----
         * CCS has type=20.  After CCS, all subsequent records in that
         * direction are encrypted.  We set the per-direction flag so
         * the code below knows to treat handshake records (type=22)
         * as encrypted rather than plaintext. */
        if (ct == TLS_CT_CHANGE_CIPHER) {
            if (is_client_to_server) {
                f->c_ccs_seen = true;
            } else {
                f->s_ccs_seen = true;
            }
            offset += this_rec_total;
            continue;
        }

        bool ccs_seen = is_client_to_server ? f->c_ccs_seen : f->s_ccs_seen;

        /* ---- Handshake tracking: ClientHello / ServerHello ----
         * ONLY for plaintext handshake records (before CCS).  After CCS,
         * handshake records (e.g. Finished) are encrypted and must be
         * handled by the decryption path below, not here. */
        if (ct == TLS_CT_HANDSHAKE && !ccs_seen && rec_len >= TLS_HDR_LEN + 4) {
            uint8_t hs_type = rec[TLS_HDR_LEN];
            if (hs_type == TLS_HS_CLIENT_HELLO && !f->have_client_random) {
                if (extract_client_random(rec, rec_len, f->client_random)) {
                    f->have_client_random = true;
                    /* Record the client endpoint (IP+port) so we can
                     * reliably determine direction for every subsequent
                     * packet on this flow.  Bug 9.3. */
                    if (pkt->net && pkt->transport) {
                        if (pkt->net->proto == NP_PROTO_IP4 && pkt->net->len >= 20) {
                            memcpy(f->client_ip, pkt->net->data + 12, 4);
                            f->client_ip_ver = 4;
                            f->client_port = sp;
                            f->have_client_endpoint = true;
                        } else if (pkt->net->proto == NP_PROTO_IP6 && pkt->net->len >= 40) {
                            memcpy(f->client_ip, pkt->net->data + 8, 16);
                            f->client_ip_ver = 6;
                            f->client_port = sp;
                            f->have_client_endpoint = true;
                        }
                    }
                    NP_LOG_DEBUG("tls_decrypt: captured client_random for flow 0x%08x",
                                 canon_key);
                    flow_maybe_derive_keys(ctx, f);
                }
            } else if (hs_type == TLS_HS_SERVER_HELLO && !f->have_cipher) {
                uint16_t cipher;
                tls_version_t ver;
                if (extract_server_hello(rec, rec_len, &cipher, &ver,
                                          f->server_random)) {
                    f->cipher_suite = cipher;
                    f->version      = ver;
                    f->have_cipher  = true;
                    f->have_server_random = true;
                    NP_LOG_DEBUG("tls_decrypt: flow 0x%08x cipher=0x%04x ver=%u",
                                 canon_key, cipher, ver);
                    flow_maybe_derive_keys(ctx, f);
                }
            }
            offset += this_rec_total;
            continue;
        }

        /* ---- Encrypted record decryption (TLS 1.2 + TLS 1.3) ----
         *
         * In TLS 1.2, after CCS, records of type 22 (Handshake — e.g.
         * Finished) and type 23 (ApplicationData) are both encrypted.
         * We must decrypt BOTH types and increment the seq counter for
         * each, because the seq number is shared across all encrypted
         * records in a direction.
         *
         * In TLS 1.3, all post-ServerHello records are type 23 and
         * encrypted. */
        if (f->version == TLS_VERSION_1_2 && !ccs_seen) {
            /* TLS 1.2 before CCS: plaintext record (e.g. ClientHello
             * that wasn't caught above, Alert, etc.) — skip. */
            offset += this_rec_total;
            continue;
        }
        if (f->version == TLS_VERSION_1_3 && ct != TLS_CT_APPLICATION) {
            /* TLS 1.3: only APPLICATION_DATA records are encrypted. */
            offset += this_rec_total;
            continue;
        }
        /* TLS 1.2 after CCS: types 22 and 23 are both encrypted.
         * TLS 1.3: only type 23.  We've already filtered above. */

        f->stat_records_total++;

        /* TLS 1.2 records carry an 8-byte explicit nonce in the fragment,
         * so the minimum fragment length is 8 + 16 (tag) = 24 bytes.
         * TLS 1.3 records have no explicit nonce; minimum is 16 (tag). */
        size_t min_frag = (f->version == TLS_VERSION_1_2)
                            ? (8 + TLS_GCM_TAG_LEN)
                            : TLS_GCM_TAG_LEN;
        if (rec_len < TLS_HDR_LEN + min_frag) {
            offset += this_rec_total;
            continue;
        }
        const uint8_t *ctext = rec + TLS_HDR_LEN;

        /* In TLS 1.3, the same outer record type (APPLICATION_DATA, 23) is
         * used for BOTH the encrypted handshake records (EncryptedExtensions
         * through Finished, encrypted with the handshake traffic secret) and
         * the actual application-data records (encrypted with the application
         * traffic secret).  We try the handshake key first; if it fails, we
         * fall back to the application key.  Each key maintains its own
         * sequence counter, so trying both does not corrupt state. */
        tls_aead_key_t *keys_to_try[2];
        uint64_t       *seqs_to_try[2];
        int             n_keys = 0;

        if (f->version == TLS_VERSION_1_3) {
            if (is_client_to_server) {
                if (f->c_hs_key.ready)  { keys_to_try[n_keys] = &f->c_hs_key;  seqs_to_try[n_keys] = &f->c_hs_seq;  n_keys++; }
                if (f->c_app_key.ready) { keys_to_try[n_keys] = &f->c_app_key; seqs_to_try[n_keys] = &f->c_app_seq; n_keys++; }
            } else {
                if (f->s_hs_key.ready)  { keys_to_try[n_keys] = &f->s_hs_key;  seqs_to_try[n_keys] = &f->s_hs_seq;  n_keys++; }
                if (f->s_app_key.ready) { keys_to_try[n_keys] = &f->s_app_key; seqs_to_try[n_keys] = &f->s_app_seq; n_keys++; }
            }
        } else {
            /* TLS 1.2: only application-traffic keys. */
            if (is_client_to_server) {
                if (f->c_app_key.ready) { keys_to_try[n_keys] = &f->c_app_key; seqs_to_try[n_keys] = &f->c_app_seq; n_keys++; }
            } else {
                if (f->s_app_key.ready) { keys_to_try[n_keys] = &f->s_app_key; seqs_to_try[n_keys] = &f->s_app_seq; n_keys++; }
            }
        }

        if (n_keys == 0) {
            offset += this_rec_total;
            continue;
        }

        size_t pt_len = 0;
        bool decrypted = false;
        for (int i = 0; i < n_keys; i++) {
            bool ok;
            if (f->version == TLS_VERSION_1_2) {
                /* TLS 1.2 GCM: 8-byte explicit nonce + ciphertext + 16-byte
                 * tag, 13-byte AAD with plaintext length.  Bug 9.1. */
                ok = aead_decrypt_tls12(keys_to_try[i], *seqs_to_try[i], ct,
                                          ctext, rec_len - TLS_HDR_LEN,
                                          plaintext, &pt_len);
            } else {
                /* TLS 1.3: ciphertext + 16-byte tag, 5-byte AAD with
                 * ciphertext length. */
                ok = aead_decrypt(keys_to_try[i], *seqs_to_try[i], ct, ctext,
                                   rec_len - TLS_HDR_LEN, plaintext, &pt_len);
            }
            if (ok) {
                (*seqs_to_try[i])++;
                decrypted = true;
                break;
            }
        }

        if (decrypted) {
            f->stat_records_decrypted++;
            ctx->stat_total_decrypted++;

            /* TLS 1.3 records have a trailing content-type byte (the actual
             * type, e.g. 23 for APPLICATION_DATA, 22 for HANDSHAKE, 21 for ALERT).
             * Strip it. */
            if (f->version == TLS_VERSION_1_3 && pt_len > 0) {
                uint8_t inner_type = plaintext[pt_len - 1];
                if (inner_type >= 20 && inner_type <= 23) {
                    pt_len--;
                }
            }

            /* Only accumulate APPLICATION_DATA plaintext on the packet.
             * Skip Finished / other handshake-message plaintext — those
             * are handshake-internal and downstream consumers (HTTP
             * parsers, etc.) don't want them in stream_data. */
            if (ct == TLS_CT_APPLICATION) {
                uint8_t *na = realloc(accumulated, accumulated_len + pt_len);
                if (na) {
                    memcpy(na + accumulated_len, plaintext, pt_len);
                    accumulated = na;
                    accumulated_len += pt_len;
                }
            }
        } else {
            f->stat_records_failed++;
            NP_LOG_DEBUG("tls_decrypt: AEAD auth failed for flow 0x%08x "
                         "(tried %d keys, direction=%s, rec_offset=%zu)",
                         canon_key, n_keys,
                         is_client_to_server ? "c2s" : "s2c", offset);
        }

        offset += this_rec_total;
    }

    free(plaintext);

    /* If we decrypted any plaintext, expose it on the packet.
     *
     * Bug H9 follow-up: if we read from pkt->stream_data, we MUST NOT
     * free it before allocating the new accumulated buffer, because
     * `buf` aliases it (and we may still be reading from `buf` in the
     * loop above — though by here the loop has exited).  We allocate
     * the new buffer first, then free the old one.  If allocation
     * fails we keep the old stream_data intact so downstream still
     * sees the (encrypted) reassembled stream. */
    if (accumulated_len > 0) {
        /* accumulated is already a fresh malloc'd buffer, so we can
         * safely free pkt->stream_data and replace. */
        if (used_stream && pkt->stream_data) {
            free(pkt->stream_data);
        }
        pkt->stream_data = accumulated;
        pkt->stream_len  = accumulated_len;

        /* Also update the underlying mutable layer. */
        for (int i = 0; i < pkt->nlayers; i++) {
            if (&pkt->layers[i] == pkt->app) {
                pkt->layers[i].data = accumulated;
                pkt->layers[i].len  = accumulated_len;
                break;
            }
        }
    } else {
        free(accumulated);
        /* Don't touch pkt->stream_data — leave it as the reassembler
         * set it.  Downstream can still see the (encrypted) stream. */
    }

    return NP_OK;
}

static void tls_free(np_processor_t *p)
{
    tls_decrypt_ctx_t *ctx = p->priv;
    if (!ctx) { free(p); return; }
    keylog_free(&ctx->keylog);
    flow_free_chain(ctx);
    pthread_mutex_destroy(&ctx->lock);
    free(ctx);
    free(p);
}

static const struct np_processor_ops tls_ops = {
    .process = tls_process,
    .free    = tls_free,
};

NP_EXPERIMENTAL
np_processor_t *np_processor_tls_decrypt(const char *keylog_path)
{
    np_processor_t *p = calloc(1, sizeof(*p));
    if (!p) return NULL;
    tls_decrypt_ctx_t *ctx = calloc(1, sizeof(*ctx));
    if (!ctx) { free(p); return NULL; }
    /* Bug M5 fix: initialize the context mutex. */
    if (pthread_mutex_init(&ctx->lock, NULL) != 0) {
        free(ctx);
        free(p);
        return NULL;
    }
    if (keylog_path) {
        keylog_load(&ctx->keylog, keylog_path);
    }
    p->ops  = &tls_ops;
    p->priv = ctx;
    return p;
}
