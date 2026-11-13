#include "GeoDbBridge.h"
#include "CityNames.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "maxminddb.h"

typedef struct {
    MMDB_s database;
    CityNames *cityNames;
} GeoDatabase;

static void copy_utf8(MMDB_entry_data_s *data, char *out, size_t size) {
    if (!out || size == 0) return;
    out[0] = '\0';
    if (!data || data->type != MMDB_DATA_TYPE_UTF8_STRING || !data->utf8_string) return;
    size_t length = data->data_size < size - 1 ? data->data_size : size - 1;
    memcpy(out, data->utf8_string, length);
    out[length] = '\0';
}

static bool localized(MMDB_entry_s *entry, const char *section, const char *locale,
                      char *out, size_t size, bool *translated) {
    MMDB_entry_data_s data = {0};
    int status = MMDB_get_value(entry, &data, section, "names", locale, NULL);
    if (translated) *translated = status == MMDB_SUCCESS && data.has_data;
    if (status != MMDB_SUCCESS || !data.has_data) {
        status = MMDB_get_value(entry, &data, section, "names", "en", NULL);
    }
    if (status != MMDB_SUCCESS || !data.has_data) return false;
    copy_utf8(&data, out, size);
    return true;
}

void *linkatlasGeoOpen(const char *path) {
    if (!path || !*path) return NULL;
    GeoDatabase *database = calloc(1, sizeof(*database));
    if (!database) return NULL;
    if (MMDB_open(path, MMDB_MODE_MMAP, &database->database) != MMDB_SUCCESS) {
        free(database);
        return NULL;
    }
    if (database->database.metadata.database_type &&
        strstr(database->database.metadata.database_type, "City")) {
        const char *slash = strrchr(path, '/');
        size_t prefix = slash ? (size_t)(slash - path) + 1 : 0;
        const char suffix[] = "city-names.tsv";
        char *namesPath = malloc(prefix + sizeof(suffix));
        if (namesPath) {
            memcpy(namesPath, path, prefix);
            memcpy(namesPath + prefix, suffix, sizeof(suffix));
            database->cityNames = cityNamesOpen(namesPath);
            free(namesPath);
        }
    }
    return database;
}

bool linkatlasGeoLookup(void *opaque, const char *ip, const char *locale, LinkAtlasGeoLookup *result) {
    if (!opaque || !ip || !result) return false;
    memset(result, 0, sizeof(*result));
    GeoDatabase *database = opaque;
    int gai_error = 0;
    int mmdb_error = 0;
    MMDB_lookup_result_s lookup = MMDB_lookup_string(&database->database, ip, &gai_error, &mmdb_error);
    if (gai_error != 0 || mmdb_error != MMDB_SUCCESS) return false;
    result->status = lookup.found_entry ? 1 : 0;
    if (!lookup.found_entry) return true;

    MMDB_entry_data_s data = {0};
    const char *language = locale && *locale ? locale : "en";
    bool cityTranslated = false;
    localized(&lookup.entry, "country", language, result->countryName, sizeof(result->countryName), NULL);
    localized(&lookup.entry, "city", language, result->city, sizeof(result->city), &cityTranslated);
    MMDB_entry_data_s subdivision = {0};
    if (MMDB_get_value(&lookup.entry, &subdivision, "subdivisions", "0", "names", language, NULL) != MMDB_SUCCESS ||
        !subdivision.has_data) {
        MMDB_get_value(&lookup.entry, &subdivision, "subdivisions", "0", "names", "en", NULL);
    }
    copy_utf8(&subdivision, result->region, sizeof(result->region));

    if (MMDB_get_value(&lookup.entry, &data, "country", "iso_code", NULL) == MMDB_SUCCESS)
        copy_utf8(&data, result->countryCode, sizeof(result->countryCode));
    if (MMDB_get_value(&lookup.entry, &data, "location", "latitude", NULL) == MMDB_SUCCESS &&
        data.has_data && data.type == MMDB_DATA_TYPE_DOUBLE) {
        result->latitude = data.double_value;
        result->hasLatitude = true;
    }
    if (MMDB_get_value(&lookup.entry, &data, "location", "longitude", NULL) == MMDB_SUCCESS &&
        data.has_data && data.type == MMDB_DATA_TYPE_DOUBLE) {
        result->longitude = data.double_value;
        result->hasLongitude = true;
    }
    if (!cityTranslated && result->hasLatitude && result->hasLongitude) {
        const char *name = cityNamesLookup(database->cityNames, result->countryCode,
                                          result->city, language, result->latitude, result->longitude);
        if (!name) {
            // DB-IP qualifies some cities as "City (District)"; GeoNames keys
            // use the plain city name, so retry without the qualifier.
            char plain[sizeof(result->city)];
            snprintf(plain, sizeof(plain), "%s", result->city);
            char *paren = strstr(plain, " (");
            if (paren) {
                *paren = '\0';
                name = cityNamesLookup(database->cityNames, result->countryCode,
                                       plain, language, result->latitude, result->longitude);
            }
        }
        if (name && strlen(name) < sizeof(result->city)) {
            memcpy(result->city, name, strlen(name) + 1);
        }
    }
    if (MMDB_get_value(&lookup.entry, &data, "autonomous_system_number", NULL) == MMDB_SUCCESS &&
        data.has_data && data.type == MMDB_DATA_TYPE_UINT32)
        result->asn = data.uint32;
    if (MMDB_get_value(&lookup.entry, &data, "autonomous_system_organization", NULL) == MMDB_SUCCESS)
        copy_utf8(&data, result->organization, sizeof(result->organization));
    return true;
}

void linkatlasGeoClose(void *opaque) {
    GeoDatabase *database = opaque;
    if (!database) return;
    MMDB_close(&database->database);
    cityNamesClose(database->cityNames);
    free(database);
}
