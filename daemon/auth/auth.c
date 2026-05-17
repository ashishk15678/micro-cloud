#pragma once

#define _GNU_SOURCE
#include "auth.h"
#include "../../include/log/log.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <sys/random.h>
#include <errno.h>


#define SHA256_BLOCK_SIZE 32

typedef struct {
    uint8_t  data[64];
    uint32_t datalen;
    uint64_t bitlen;
    uint32_t state[8];
} sha256_ctx;

static const uint32_t SHA256_K[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,
    0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,
    0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,
    0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,
    0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,
    0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,
    0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,
    0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,
    0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2,
};

#define ROTRIGHT(a,b)  (((a) >> (b)) | ((a) << (32-(b))))
#define CH(x,y,z)      (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z)     (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x)         (ROTRIGHT(x,2)  ^ ROTRIGHT(x,13) ^ ROTRIGHT(x,22))
#define EP1(x)         (ROTRIGHT(x,6)  ^ ROTRIGHT(x,11) ^ ROTRIGHT(x,25))
#define SIG0(x)        (ROTRIGHT(x,7)  ^ ROTRIGHT(x,18) ^ ((x) >> 3))
#define SIG1(x)        (ROTRIGHT(x,17) ^ ROTRIGHT(x,19) ^ ((x) >> 10))

static void sha256_transform(sha256_ctx *ctx, const uint8_t data[64])
{
    uint32_t a,b,c,d,e,f,g,h,i,j,t1,t2,m[64];
    for (i=0,j=0;i<16;++i,j+=4)
        m[i] = ((uint32_t)data[j]<<24)|((uint32_t)data[j+1]<<16)
              |((uint32_t)data[j+2]<<8)|(uint32_t)data[j+3];
    for (;i<64;++i)
        m[i]=SIG1(m[i-2])+m[i-7]+SIG0(m[i-15])+m[i-16];
    a=ctx->state[0];b=ctx->state[1];c=ctx->state[2];d=ctx->state[3];
    e=ctx->state[4];f=ctx->state[5];g=ctx->state[6];h=ctx->state[7];
    for (i=0;i<64;++i){
        t1=h+EP1(e)+CH(e,f,g)+SHA256_K[i]+m[i];
        t2=EP0(a)+MAJ(a,b,c);
        h=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+t2;
    }
    ctx->state[0]+=a;ctx->state[1]+=b;ctx->state[2]+=c;ctx->state[3]+=d;
    ctx->state[4]+=e;ctx->state[5]+=f;ctx->state[6]+=g;ctx->state[7]+=h;
}

static void sha256_init(sha256_ctx *ctx)
{
    ctx->datalen=0; ctx->bitlen=0;
    ctx->state[0]=0x6a09e667;ctx->state[1]=0xbb67ae85;
    ctx->state[2]=0x3c6ef372;ctx->state[3]=0xa54ff53a;
    ctx->state[4]=0x510e527f;ctx->state[5]=0x9b05688c;
    ctx->state[6]=0x1f83d9ab;ctx->state[7]=0x5be0cd19;
}

static void sha256_update(sha256_ctx *ctx, const uint8_t *data, size_t len)
{
    for (size_t i=0;i<len;++i){
        ctx->data[ctx->datalen++]=data[i];
        if(ctx->datalen==64){sha256_transform(ctx,ctx->data);ctx->bitlen+=512;ctx->datalen=0;}
    }
}

static void sha256_final(sha256_ctx *ctx, uint8_t hash[SHA256_BLOCK_SIZE])
{
    uint32_t i=ctx->datalen;
    if(ctx->datalen<56){
        ctx->data[i++]=0x80;
        while(i<56) ctx->data[i++]=0x00;
    } else {
        ctx->data[i++]=0x80;
        while(i<64) ctx->data[i++]=0x00;
        sha256_transform(ctx,ctx->data);
        memset(ctx->data,0,56);
    }
    ctx->bitlen+=ctx->datalen*8;
    ctx->data[63]=(uint8_t)(ctx->bitlen);
    ctx->data[62]=(uint8_t)(ctx->bitlen>>8);
    ctx->data[61]=(uint8_t)(ctx->bitlen>>16);
    ctx->data[60]=(uint8_t)(ctx->bitlen>>24);
    ctx->data[59]=(uint8_t)(ctx->bitlen>>32);
    ctx->data[58]=(uint8_t)(ctx->bitlen>>40);
    ctx->data[57]=(uint8_t)(ctx->bitlen>>48);
    ctx->data[56]=(uint8_t)(ctx->bitlen>>56);
    sha256_transform(ctx,ctx->data);
    for(i=0;i<4;++i){
        hash[i]   =(uint8_t)(ctx->state[0]>>(24-i*8));
        hash[i+4] =(uint8_t)(ctx->state[1]>>(24-i*8));
        hash[i+8] =(uint8_t)(ctx->state[2]>>(24-i*8));
        hash[i+12]=(uint8_t)(ctx->state[3]>>(24-i*8));
        hash[i+16]=(uint8_t)(ctx->state[4]>>(24-i*8));
        hash[i+20]=(uint8_t)(ctx->state[5]>>(24-i*8));
        hash[i+24]=(uint8_t)(ctx->state[6]>>(24-i*8));
        hash[i+28]=(uint8_t)(ctx->state[7]>>(24-i*8));
    }
}

static void hmac_sha256(const uint8_t *key, size_t klen,
                         const uint8_t *msg, size_t mlen,
                         uint8_t out[SHA256_BLOCK_SIZE])
{
    uint8_t k_ipad[64], k_opad[64];
    uint8_t tmp_key[SHA256_BLOCK_SIZE];

    /* If key > 64 bytes, hash it first */
    if (klen > 64) {
        sha256_ctx h; sha256_init(&h);
        sha256_update(&h, key, klen);
        sha256_final(&h, tmp_key);
        key  = tmp_key;
        klen = SHA256_BLOCK_SIZE;
    }

    memset(k_ipad, 0x36, 64);
    memset(k_opad, 0x5c, 64);
    for (size_t i = 0; i < klen; i++) {
        k_ipad[i] ^= key[i];
        k_opad[i] ^= key[i];
    }

    uint8_t inner[SHA256_BLOCK_SIZE];
    sha256_ctx h;
    sha256_init(&h);
    sha256_update(&h, k_ipad, 64);
    sha256_update(&h, msg, mlen);
    sha256_final(&h, inner);

    sha256_init(&h);
    sha256_update(&h, k_opad, 64);
    sha256_update(&h, inner, SHA256_BLOCK_SIZE);
    sha256_final(&h, out);

    IS_memzero(k_ipad, sizeof(k_ipad));
    IS_memzero(k_opad, sizeof(k_opad));
    IS_memzero(inner,  sizeof(inner));
}

static void pbkdf2_sha256(const uint8_t *pass, size_t plen,
                           const uint8_t *salt, size_t slen,
                           uint32_t iter, uint8_t *out, size_t dklen)
{
    /* For our use-case dklen == SHA256_BLOCK_SIZE, so only block 1 needed */
    uint8_t U[SHA256_BLOCK_SIZE];
    uint8_t T[SHA256_BLOCK_SIZE];
    uint8_t S[256];  /* salt + 4-byte block counter */

    size_t slen_safe = slen < 252 ? slen : 252;
    memcpy(S, salt, slen_safe);
    S[slen_safe]   = 0;
    S[slen_safe+1] = 0;
    S[slen_safe+2] = 0;
    S[slen_safe+3] = 1;  /* block index = 1, big-endian */

    /* U1 = HMAC(pass, salt || INT(1)) */
    hmac_sha256(pass, plen, S, slen_safe + 4, U);
    memcpy(T, U, SHA256_BLOCK_SIZE);

    for (uint32_t c = 1; c < iter; c++) {
        uint8_t prev[SHA256_BLOCK_SIZE];
        memcpy(prev, U, SHA256_BLOCK_SIZE);
        hmac_sha256(pass, plen, prev, SHA256_BLOCK_SIZE, U);
        for (int i = 0; i < SHA256_BLOCK_SIZE; i++) T[i] ^= U[i];
        IS_memzero(prev, sizeof(prev));
    }

    size_t copy = dklen < SHA256_BLOCK_SIZE ? dklen : SHA256_BLOCK_SIZE;
    memcpy(out, T, copy);
    IS_memzero(T, sizeof(T));
    IS_memzero(U, sizeof(U));
}

static const char B64_CHARS[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static void base64_encode(const uint8_t *in, size_t inlen, char *out, size_t outlen)
{
    size_t i, j = 0;
    for (i = 0; i < inlen && j + 4 < outlen; i += 3) {
        uint32_t val = (uint32_t)in[i] << 16;
        if (i + 1 < inlen) val |= (uint32_t)in[i+1] << 8;
        if (i + 2 < inlen) val |= (uint32_t)in[i+2];
        out[j++] = B64_CHARS[(val >> 18) & 0x3F];
        out[j++] = B64_CHARS[(val >> 12) & 0x3F];
        out[j++] = (i + 1 < inlen) ? B64_CHARS[(val >> 6) & 0x3F] : '=';
        out[j++] = (i + 2 < inlen) ? B64_CHARS[val & 0x3F]        : '=';
    }
    if (j < outlen) out[j] = '\0';
}

static uint8_t g_signing_key[32];
static bool    g_auth_initialised = false;

IS_err_t auth_init(void)
{
    ssize_t n = getrandom(g_signing_key, sizeof(g_signing_key), GRND_RANDOM);
    if (n != (ssize_t)sizeof(g_signing_key)) {
        ERROR("getrandom for signing key: %s", strerror(errno));
        return IS_ERR_IO;
    }
    g_auth_initialised = true;
    INFO("auth signing key initialised");
    return IS_OK;
}

IS_err_t auth_hash_password(const char *password, char *out, size_t outlen)
{
    if (!password || !out || outlen < 128) return IS_ERR_INVAL;

    uint8_t salt[IS_SALT_BYTES];
    ssize_t n = getrandom(salt, sizeof(salt), 0);
    if (n != (ssize_t)sizeof(salt)) return IS_ERR_IO;

    uint8_t hash[IS_HASH_BYTES];
    pbkdf2_sha256((const uint8_t *)password, strlen(password),
                   salt, sizeof(salt),
                   IS_PBKDF2_ITER, hash, sizeof(hash));

    char salt_b64[64], hash_b64[64];
    base64_encode(salt, sizeof(salt), salt_b64, sizeof(salt_b64));
    base64_encode(hash, sizeof(hash), hash_b64, sizeof(hash_b64));

    int ret = snprintf(out, outlen, "$pbkdf2-sha256$%u$%s$%s",
                       IS_PBKDF2_ITER, salt_b64, hash_b64);
    IS_memzero(hash, sizeof(hash));
    IS_memzero(salt, sizeof(salt));

    if (ret < 0 || (size_t)ret >= outlen) return IS_ERR_TRUNC;
    return IS_OK;
}

IS_err_t auth_verify_password(const char *password, const char *encoded)
{
    if (!password || !encoded) return IS_ERR_AUTH;
    if (strncmp(encoded, "$pbkdf2-sha256$", 15) != 0) return IS_ERR_AUTH;

    unsigned int iter = 0;
    char salt_b64[64] = {0}, stored_hash_b64[64] = {0};
    int parsed = sscanf(encoded + 15, "%u$%63[^$]$%63s",
                        &iter, salt_b64, stored_hash_b64);
    if (parsed != 3 || iter == 0) return IS_ERR_AUTH;

    uint8_t derived[IS_HASH_BYTES];
    pbkdf2_sha256((const uint8_t *)password, strlen(password),
                   (const uint8_t *)salt_b64, strlen(salt_b64),
                   iter, derived, sizeof(derived));

    char derived_b64[64];
    base64_encode(derived, sizeof(derived), derived_b64, sizeof(derived_b64));

    bool ok = IS_ct_memeq(derived_b64, stored_hash_b64,
                               strlen(stored_hash_b64));
    IS_memzero(derived, sizeof(derived));
    IS_memzero(derived_b64, sizeof(derived_b64));

    return ok ? IS_OK : IS_ERR_AUTH;
}

static void hex_encode(const uint8_t *in, size_t inlen, char *out, size_t outlen)
{
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < inlen && (i * 2 + 2) < outlen; i++) {
        out[i * 2]     = hex[in[i] >> 4];
        out[i * 2 + 1] = hex[in[i] & 0x0F];
    }
    out[inlen * 2 < outlen ? inlen * 2 : outlen - 1] = '\0';
}

IS_err_t auth_token_issue(IS_db_t *db, const char *user_id,
                               char *token_out, int64_t *expires_out)
{
    if (!g_auth_initialised) return IS_ERR_INTERNAL;
    if (!db || !user_id || !token_out || !expires_out) return IS_ERR_INVAL;

    /* 32 bytes of entropy */
    uint8_t rand_bytes[IS_TOKEN_BYTES];
    ssize_t n = getrandom(rand_bytes, sizeof(rand_bytes), 0);
    if (n != (ssize_t)sizeof(rand_bytes)) return IS_ERR_IO;

    /* HMAC-SHA256(signing_key, rand_bytes) for integrity */
    uint8_t sig[SHA256_BLOCK_SIZE];
    hmac_sha256(g_signing_key, sizeof(g_signing_key),
                rand_bytes, sizeof(rand_bytes), sig);

    /* Token = hex(rand_bytes) + "." + hex(sig) */
    char rand_hex[IS_TOKEN_BYTES * 2 + 1];
    char sig_hex[SHA256_BLOCK_SIZE * 2 + 1];
    hex_encode(rand_bytes, sizeof(rand_bytes), rand_hex, sizeof(rand_hex));
    hex_encode(sig,        SHA256_BLOCK_SIZE,  sig_hex,  sizeof(sig_hex));

    int r = snprintf(token_out, IS_TOKEN_HEX_LEN * 2,
                     "%s.%s", rand_hex, sig_hex);
    if (r <= 0) { IS_memzero(rand_bytes, sizeof(rand_bytes)); return IS_ERR_INTERNAL; }

    int64_t now        = (int64_t)time(NULL);
    int64_t expires_at = now + IS_TOKEN_TTL_SEC;
    *expires_out       = expires_at;

    /* Store in DB */
    IS_uuid_t token_id;
    IS_uuid_generate(&token_id);
    char token_id_str[IS_UUID_STR_LEN];
    IS_uuid_to_str(&token_id, token_id_str);

    db_token_t dbt;
    memset(&dbt, 0, sizeof(dbt));
    memcpy(dbt.id,      token_id_str, sizeof(dbt.id));
    memcpy(dbt.user_id, user_id,      sizeof(dbt.user_id) - 1);
    memcpy(dbt.value,   token_out,    sizeof(dbt.value) - 1);
    dbt.expires_at = expires_at;

    IS_memzero(rand_bytes, sizeof(rand_bytes));
    IS_memzero(sig, sizeof(sig));

    IS_err_t err = db_token_create(db, &dbt);
    IS_memzero(&dbt, sizeof(dbt));
    return err;
}

IS_err_t auth_token_validate(IS_db_t *db, const char *token,
                                  char user_id_out[IS_UUID_STR_LEN],
                                  int  *role_out)
{
    if (!db || !token || !user_id_out || !role_out) return IS_ERR_INVAL;

    /* Check token length to prevent oversized input */
    size_t tlen = strnlen(token, 256);
    if (tlen == 0 || tlen >= 256) return IS_ERR_AUTH;

    /* Purge expired tokens periodically (best-effort) */
    db_token_purge_expired(db);

    db_token_t dbt;
    IS_err_t err = db_token_get(db, token, &dbt);
    if (err != IS_OK) return IS_ERR_AUTH;

    int64_t now = (int64_t)time(NULL);
    if (dbt.expires_at <= now) {
        db_token_delete(db, token);
        return IS_ERR_AUTH;
    }

    if (!IS_ct_memeq(dbt.value, token, tlen)) return IS_ERR_AUTH;
    db_user_t usr;
    err = db_user_get_by_id(db, dbt.user_id, &usr);
    if (err != IS_OK) return IS_ERR_AUTH;

    memcpy(user_id_out, dbt.user_id, IS_UUID_STR_LEN);
    *role_out = usr.role;
    return IS_OK;
}

IS_err_t auth_token_revoke(IS_db_t *db, const char *token)
{
    if (!db || !token) return IS_ERR_INVAL;
    db_token_delete(db, token);
    return IS_OK;
}
