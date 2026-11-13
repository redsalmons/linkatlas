#ifndef LINKATLAS_CITY_NAMES_H
#define LINKATLAS_CITY_NAMES_H

#include <stddef.h>

typedef struct CityNames CityNames;

/* Optional, immutable offline name supplement. Missing/invalid files return NULL. */
CityNames *cityNamesOpen(const char *path);
void cityNamesClose(CityNames *names);
/* Returned text belongs to names. Country/name must match; coordinates only
 * disambiguate namesakes. No location coordinates are changed by this lookup. */
const char *cityNamesLookup(const CityNames *names, const char *country,
                           const char *city, const char *locale,
                           double latitude, double longitude);

#endif
