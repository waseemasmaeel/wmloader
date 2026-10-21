#ifndef WMCRYPTO_H
#define WMCRYPTO_H

#include <stdint.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

/* Format v2: MAGIC(5) | key_version(1) | bind_flag(1, 0 or 1) |
 * salt(16) | iv(12) | tag(16) | ciphertext
 * key_version lets a server hold several secret keys at once so a key
 * can be rotated without breaking files encrypted under the old one.
 * bind_flag: when 1, the file was encrypted with this server's declared
 * identity string as AEAD associated data - decryption only succeeds if
 * the loader's *locally computed* identity matches exactly (the identity
 * string itself is never stored in the file; only the "is bound" bit is).
 * This ties a file to one deployment target without a separate license
 * server, and fails the SAME way tampering does (a GCM tag mismatch) -
 * there is deliberately no soft-fail/grace-period path here, since that
 * needs persistent state a plain file-encryption tool has no business
 * keeping; see README for when a real license layer would be warranted
 * instead of this. */
#define WM_MAGIC        "WMEX2"
#define WM_MAGIC_LEN    5
#define WM_VER_LEN      1
#define WM_BIND_LEN     1
#define WM_SALT_LEN     16
#define WM_IV_LEN       12
#define WM_TAG_LEN      16
#define WM_KEY_LEN      32
#define WM_HKDF_INFO    "wmloader-v1-file-key"
#define WM_HEADER_LEN   (WM_MAGIC_LEN + WM_VER_LEN + WM_BIND_LEN)
#define WM_BLOB_OVERHEAD (WM_SALT_LEN + WM_IV_LEN + WM_TAG_LEN)

static inline int wm_hkdf_sha256(const unsigned char *ikm, size_t ikm_len,
                                  const unsigned char *salt, size_t salt_len,
                                  unsigned char out_key[WM_KEY_LEN])
{
    unsigned char prk[EVP_MAX_MD_SIZE];
    unsigned int prk_len = 0;
    if (!HMAC(EVP_sha256(), salt, (int)salt_len, ikm, ikm_len, prk, &prk_len)) {
        return 0;
    }
    unsigned char info_block[256];
    size_t info_len = strlen(WM_HKDF_INFO);
    if (info_len + 1 > sizeof(info_block)) return 0;
    memcpy(info_block, WM_HKDF_INFO, info_len);
    info_block[info_len] = 0x01;

    unsigned char t1[EVP_MAX_MD_SIZE];
    unsigned int t1_len = 0;
    if (!HMAC(EVP_sha256(), prk, prk_len, info_block, info_len + 1, t1, &t1_len)) {
        return 0;
    }
    if (t1_len < WM_KEY_LEN) return 0;
    memcpy(out_key, t1, WM_KEY_LEN);
    return 1;
}

static inline size_t wm_encrypt_aad(const unsigned char *secret, size_t secret_len,
                                     const unsigned char *aad, size_t aad_len,
                                     const unsigned char *plaintext, size_t plaintext_len,
                                     unsigned char *out)
{
    unsigned char salt[WM_SALT_LEN], iv[WM_IV_LEN], key[WM_KEY_LEN], tag[WM_TAG_LEN];
    if (!RAND_bytes(salt, WM_SALT_LEN)) return 0;
    if (!RAND_bytes(iv, WM_IV_LEN)) return 0;
    if (!wm_hkdf_sha256(secret, secret_len, salt, WM_SALT_LEN, key)) return 0;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return 0;
    int len = 0, ct_len = 0;
    size_t total = 0;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) goto fail;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, WM_IV_LEN, NULL) != 1) goto fail;
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv) != 1) goto fail;
    if (aad_len > 0 && EVP_EncryptUpdate(ctx, NULL, &len, aad, (int)aad_len) != 1) goto fail;

    memcpy(out, salt, WM_SALT_LEN);
    memcpy(out + WM_SALT_LEN, iv, WM_IV_LEN);

    if (EVP_EncryptUpdate(ctx, out + WM_SALT_LEN + WM_IV_LEN + WM_TAG_LEN, &len,
                           plaintext, (int)plaintext_len) != 1) goto fail;
    ct_len = len;
    if (EVP_EncryptFinal_ex(ctx, out + WM_SALT_LEN + WM_IV_LEN + WM_TAG_LEN + ct_len, &len) != 1) goto fail;
    ct_len += len;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, WM_TAG_LEN, tag) != 1) goto fail;
    memcpy(out + WM_SALT_LEN + WM_IV_LEN, tag, WM_TAG_LEN);

    total = WM_SALT_LEN + WM_IV_LEN + WM_TAG_LEN + (size_t)ct_len;
    EVP_CIPHER_CTX_free(ctx);
    return total;

fail:
    EVP_CIPHER_CTX_free(ctx);
    return 0;
}

static inline size_t wm_encrypt(const unsigned char *secret, size_t secret_len,
                                 const unsigned char *plaintext, size_t plaintext_len,
                                 unsigned char *out)
{
    return wm_encrypt_aad(secret, secret_len, NULL, 0, plaintext, plaintext_len, out);
}

static inline size_t wm_decrypt_aad(const unsigned char *secret, size_t secret_len,
                                     const unsigned char *aad, size_t aad_len,
                                     const unsigned char *blob, size_t blob_len,
                                     unsigned char *out)
{
    if (blob_len < WM_BLOB_OVERHEAD) return 0;

    const unsigned char *salt = blob;
    const unsigned char *iv   = blob + WM_SALT_LEN;
    const unsigned char *tag  = blob + WM_SALT_LEN + WM_IV_LEN;
    const unsigned char *ct   = blob + WM_BLOB_OVERHEAD;
    size_t ct_len = blob_len - WM_BLOB_OVERHEAD;

    unsigned char key[WM_KEY_LEN];
    if (!wm_hkdf_sha256(secret, secret_len, salt, WM_SALT_LEN, key)) return 0;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return 0;
    int len = 0, pt_len = 0;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) goto fail;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, WM_IV_LEN, NULL) != 1) goto fail;
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv) != 1) goto fail;
    if (aad_len > 0 && EVP_DecryptUpdate(ctx, NULL, &len, aad, (int)aad_len) != 1) goto fail;
    if (EVP_DecryptUpdate(ctx, out, &len, ct, (int)ct_len) != 1) goto fail;
    pt_len = len;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, WM_TAG_LEN, (void *)tag) != 1) goto fail;
    if (EVP_DecryptFinal_ex(ctx, out + pt_len, &len) != 1) goto fail;
    pt_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return (size_t)pt_len;

fail:
    EVP_CIPHER_CTX_free(ctx);
    OPENSSL_cleanse(out, blob_len);
    return 0;
}

static inline size_t wm_decrypt(const unsigned char *secret, size_t secret_len,
                                 const unsigned char *blob, size_t blob_len,
                                 unsigned char *out)
{
    return wm_decrypt_aad(secret, secret_len, NULL, 0, blob, blob_len, out);
}

#endif
