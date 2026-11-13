#ifndef GEO_DB_BRIDGE_H
#define GEO_DB_BRIDGE_H

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    int status;
    char countryCode[8];
    char countryName[96];
    char region[96];
    char city[96];
    double latitude;
    double longitude;
    bool hasLatitude;
    bool hasLongitude;
    uint64_t asn;
    char organization[128];
} LinkAtlasGeoLookup;

void *linkatlasGeoOpen(const char *path);
bool linkatlasGeoLookup(void *database, const char *ip, const char *locale, LinkAtlasGeoLookup *result);
void linkatlasGeoClose(void *database);

#ifdef __cplusplus
}
#endif

#endif
