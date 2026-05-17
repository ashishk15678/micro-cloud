/*
 * src/identity/auth.h — authentication primitives
 *
 * Password storage : PBKDF2-SHA256 with 310 000 iterations and 32-byte salt.
 * Tokens           : 32 bytes of getrandom(2) entropy, HMAC-SHA256 signed,
 *                    hex-encoded, stored in the DB with TTL.
 * All comparisons  : constant-time to prevent timing side-channels.
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef IS_AUTH_H
#define IS_AUTH_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "../utils/defaults.h"
#include "db/db.h"

/* ── Password hashing ─────────────────────────────────────────────────────── */

/**
 * Hash @password using PBKDF2-SHA256.
 * Output is an encoded string:  "$pbkdf2-sha256$<iter>$<salt_b64>$<hash_b64>"
 * suitable for storage in the database.
 *
 * @out     buffer to receive encoded hash
 * @outlen  size of @out — must be ≥ 128 bytes
 */
IS_err_t auth_hash_password(const char *password,
                                 char *out, size_t outlen);

/**
 * Verify @password against an encoded hash produced by auth_hash_password().
 * Returns IS_OK if the password matches, IS_ERR_AUTH otherwise.
 * Comparison is constant-time.
 */
IS_err_t auth_verify_password(const char *password, const char *encoded_hash);

/* ── Token lifecycle ──────────────────────────────────────────────────────── */

/**
 * Issue a new token for @user_id.
 * Generates 32 bytes from getrandom(2), signs with HMAC-SHA256 over
 * a per-process secret key, and writes the result to the DB.
 *
 * @token_out  buffer of at least IS_TOKEN_HEX_LEN bytes
 * @expires_out  set to Unix timestamp of expiry
 */
IS_err_t auth_token_issue(IS_db_t *db, const char *user_id,
                               char *token_out, int64_t *expires_out);

/**
 * Validate a token string.
 * Checks DB existence, TTL, and HMAC signature (constant-time).
 * On success, fills *user_id_out with the owning user's UUID and
 * *role_out with their role.
 */
IS_err_t auth_token_validate(IS_db_t *db, const char *token,
                                  char user_id_out[IS_UUID_STR_LEN],
                                  int  *role_out);

/**
 * Revoke a token.  Returns IS_OK even if the token was already absent.
 */
IS_err_t auth_token_revoke(IS_db_t *db, const char *token);

/* ── Misc ─────────────────────────────────────────────────────────────────── */

/** Initialise the per-process HMAC signing key from getrandom(). */
IS_err_t auth_init(void);

#endif /* IS_AUTH_H */
