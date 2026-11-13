#ifndef MAXMINDDB_CONFIG_H
#define MAXMINDDB_CONFIG_H

#define PACKAGE_VERSION "1.12.2"

#ifndef _WIN32
#define HAVE_MMAP 1
#endif

#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define MMDB_LITTLE_ENDIAN 1
#else
#define MMDB_LITTLE_ENDIAN 0
#endif

#endif
