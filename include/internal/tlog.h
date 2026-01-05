/*
 * Copyright 2024 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

#ifndef OSSL_INTERNAL_TLOG_H
#define OSSL_INTERNAL_TLOG_H

#include <stdio.h>
#include <string.h>

/* Tongsuo Debug Logging Macros */

/* Helper to extract filename from path */
#if defined(_WIN32) || defined(WIN64)
# define TLOG_FILENAME(x) (strrchr(x, '\\') ? strrchr(x, '\\') + 1 : x)
#else
# define TLOG_FILENAME(x) (strrchr(x, '/') ? strrchr(x, '/') + 1 : x)
#endif

#ifdef _MSC_VER
# define TLOG_LOG(level, fmt, ...) \
    fprintf(stderr, level ": %s:%d: " fmt "\n", TLOG_FILENAME(__FILE__), __LINE__, __VA_ARGS__)
#else
# define TLOG_LOG(level, fmt, ...) \
    fprintf(stderr, level ": %s:%d: " fmt "\n", TLOG_FILENAME(__FILE__), __LINE__, ##__VA_ARGS__)
#endif

#ifdef TLOG_ENABLE_DEBUG
# ifdef _MSC_VER
#  define TLOG_DEBUG(fmt, ...) TLOG_LOG("TLOG_DEBUG", fmt, __VA_ARGS__)
#  define TLOG_INFO(fmt, ...)  TLOG_LOG("TLOG_INFO", fmt, __VA_ARGS__)
#  define TLOG_WARN(fmt, ...)  TLOG_LOG("TLOG_WARN", fmt, __VA_ARGS__)
#  define TLOG_ERROR(fmt, ...) TLOG_LOG("TLOG_ERROR", fmt, __VA_ARGS__)
# else
#  define TLOG_DEBUG(fmt, ...) TLOG_LOG("TLOG_DEBUG", fmt, ##__VA_ARGS__)
#  define TLOG_INFO(fmt, ...)  TLOG_LOG("TLOG_INFO", fmt, ##__VA_ARGS__)
#  define TLOG_WARN(fmt, ...)  TLOG_LOG("TLOG_WARN", fmt, ##__VA_ARGS__)
#  define TLOG_ERROR(fmt, ...) TLOG_LOG("TLOG_ERROR", fmt, ##__VA_ARGS__)
# endif
#else
# define TLOG_DEBUG(fmt, ...)
# define TLOG_INFO(fmt, ...)
# define TLOG_WARN(fmt, ...)
# define TLOG_ERROR(fmt, ...)
#endif

/* Helper macro for printing hex data */
#ifdef TLOG_ENABLE_DEBUG
# define TLOG_HEX(level, desc, data, len) do { \
    fprintf(stderr, "[%s] %s (%zu bytes): ", level, desc, (size_t)(len)); \
    for (size_t _i = 0; _i < (size_t)(len) && _i < len; _i++) { \
        fprintf(stderr, "%02X ", ((unsigned char*)(data))[_i]); \
    } \
    fprintf(stderr, "\n"); \
} while(0)

# define TLOG_DEBUG_HEX(desc, data, len) TLOG_HEX("DEBUG", desc, data, len)
# define TLOG_INFO_HEX(desc, data, len) TLOG_HEX("INFO", desc, data, len)
#else
# define TLOG_DEBUG_HEX(desc, data, len)
# define TLOG_INFO_HEX(desc, data, len)
#endif

#endif /* OSSL_INTERNAL_TLOG_H */
