// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Aman Deep (amdeep.dev@gmail.com)
// SPDX-FileCopyrightText: 2026 Ashish Kumar <15678ashishk@gmail.com>

#pragma once

#include <stddef.h>

int password_hash(const char *password, char *out, size_t outlen);
int password_verify(const char *password, const char *encoded);
