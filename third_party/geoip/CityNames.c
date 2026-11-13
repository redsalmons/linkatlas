#include "CityNames.h"

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    char *key;
    char *name;
    double latitude;
    double longitude;
} CityName;

struct CityNames {
    char *text;
    CityName *entries;
    size_t count;
};

void cityNamesClose(CityNames *names) {
    if (!names) return;
    free(names->entries);
    free(names->text);
    free(names);
}

CityNames *cityNamesOpen(const char *path) {
    FILE *file = fopen(path, "rb");
    if (!file) return NULL;
    CityNames *names = calloc(1, sizeof(*names));
    if (!names) { fclose(file); return NULL; }
    if (fseek(file, 0, SEEK_END) != 0) goto fail;
    long size = ftell(file);
    if (size <= 0 || size > 64 * 1024 * 1024 || fseek(file, 0, SEEK_SET) != 0) goto fail;
    names->text = malloc((size_t)size + 1);
    if (!names->text || fread(names->text, 1, (size_t)size, file) != (size_t)size) goto fail;
    names->text[size] = '\0';
    size_t capacity = 1;
    for (long i = 0; i < size; ++i) if (names->text[i] == '\n') ++capacity;
    names->entries = calloc(capacity, sizeof(*names->entries));
    if (!names->entries) goto fail;
    char *cursor = names->text;
    char *line;
    while ((line = strsep(&cursor, "\n")) != NULL) {
        if (*line == '#' || *line == '\0') continue;
        char *fields = line;
        char *key = strsep(&fields, "\t");
        char *lat = strsep(&fields, "\t");
        char *lon = strsep(&fields, "\t");
        char *name = strsep(&fields, "\t");
        if (!lat || !lon || !name || fields || !*key || !*name) goto fail;
        char *end;
        double latitude = strtod(lat, &end);
        if (end == lat || *end || !isfinite(latitude) || fabs(latitude) > 90) goto fail;
        double longitude = strtod(lon, &end);
        if (end == lon || *end || !isfinite(longitude) || fabs(longitude) > 180) goto fail;
        if (names->count && strcmp(names->entries[names->count - 1].key, key) > 0) goto fail;
        names->entries[names->count++] = (CityName){key, name, latitude, longitude};
    }
    fclose(file);
    return names;
fail:
    fclose(file);
    cityNamesClose(names);
    return NULL;
}

const char *cityNamesLookup(const CityNames *names, const char *country,
                           const char *city, const char *locale,
                           double latitude, double longitude) {
    if (!names || !country || !city || !locale ||
        !isfinite(latitude) || !isfinite(longitude) ||
        fabs(latitude) > 90 || fabs(longitude) > 180) return NULL;
    char key[512];
    int length = snprintf(key, sizeof(key), "%s|%s|%s", country, city, locale);
    if (length < 0 || (size_t)length >= sizeof(key)) return NULL;
    // ASCII-only normalization matches the generator regardless of system locale.
    for (size_t i = strlen(country) + 1; key[i] && key[i] != '|'; ++i)
        if (key[i] >= 'A' && key[i] <= 'Z') key[i] += 'a' - 'A';
    size_t low = 0, high = names->count;
    while (low < high) {
        size_t middle = low + (high - low) / 2;
        if (strcmp(names->entries[middle].key, key) < 0) low = middle + 1;
        else high = middle;
    }
    const char *translation = NULL;
    // Require the exact name/country AND proximity; never rename an unrelated
    // suburb or a distant namesake just because it is the nearest known city.
    const double radians = 3.14159265358979323846 / 180;
    const double earthRadiusKm = 6371.0;
    double closestKm = 50;
    for (size_t i = low; i < names->count && strcmp(names->entries[i].key, key) == 0; ++i) {
        const CityName *entry = &names->entries[i];
        double lat = (entry->latitude - latitude) * radians;
        double lon = (entry->longitude - longitude) * radians;
        double a = sin(lat / 2) * sin(lat / 2) +
            cos(latitude * radians) * cos(entry->latitude * radians) *
            sin(lon / 2) * sin(lon / 2);
        double distance = 2 * earthRadiusKm * asin(sqrt(fmin(1, fmax(0, a))));
        if (distance < closestKm) {
            closestKm = distance;
            translation = entry->name;
        }
    }
    return translation;
}
