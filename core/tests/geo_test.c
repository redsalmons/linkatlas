#include "CityNames.h"
#include "GeoDbBridge.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv) {
    char directory[] = "/tmp/linkatlas-geo-test-XXXXXX";
    assert(mkdtemp(directory));
    char table[512];
    snprintf(table, sizeof(table), "%s/city-names.tsv", directory);
    FILE *file = fopen(table, "w");
    assert(file);
    fputs("# fixture\n"
          "CN|hangzhou|zh-CN\t30.2742\t120.155\t杭州\n"
          "US|springfield|zh-CN\t39.8\t-89.65\t斯普林菲尔德（伊利诺伊州）\n"
          "US|springfield|zh-CN\t42.1\t-72.58\t斯普林菲尔德（马萨诸塞州）\n", file);
    fclose(file);
    CityNames *names = cityNamesOpen(table);
    assert(names);
    assert(strcmp(cityNamesLookup(names, "CN", "Hangzhou", "zh-CN", 30.27, 120.15), "杭州") == 0);
    assert(strcmp(cityNamesLookup(names, "US", "Springfield", "zh-CN", 39.81, -89.64),
                  "斯普林菲尔德（伊利诺伊州）") == 0);
    assert(strcmp(cityNamesLookup(names, "US", "Springfield", "zh-CN", 42.09, -72.57),
                  "斯普林菲尔德（马萨诸塞州）") == 0);
    assert(!cityNamesLookup(names, "US", "Springfield", "zh-CN", 30, -120));
    assert(!cityNamesLookup(names, "US", "Hangzhou", "zh-CN", 30.27, 120.15));
    assert(!cityNamesLookup(names, "CN", "Unknown suburb", "zh-CN", 30.27, 120.15));
    assert(!cityNamesLookup(names, "CN", "Hangzhou", "fr", 30.27, 120.15));
    cityNamesClose(names);
    file = fopen(table, "w");
    assert(file);
    fputs("invalid\tcoordinate\t120\tname\n", file);
    fclose(file);
    assert(!cityNamesOpen(table));
    unlink(table);
    assert(!cityNamesOpen(table));

    if (argc == 3) {
        char database[512];
        snprintf(database, sizeof(database), "%s/city.mmdb", directory);
        assert(symlink(argv[1], database) == 0);
        assert(symlink(argv[2], table) == 0);
        void *reader = linkatlasGeoOpen(database);
        assert(reader);
        const char *addresses[] = {"223.5.5.5", "8.8.8.8", "1.1.1.1"};
        for (size_t i = 0; i < sizeof(addresses) / sizeof(addresses[0]); ++i) {
            LinkAtlasGeoLookup en, zh;
            assert(linkatlasGeoLookup(reader, addresses[i], "en", &en));
            assert(linkatlasGeoLookup(reader, addresses[i], "zh-CN", &zh));
            assert(en.status == 1 && zh.status == 1);
            assert(zh.city[0] && strcmp(en.city, zh.city) != 0);
            assert(en.latitude == zh.latitude && en.longitude == zh.longitude);
            printf("%s: %s -> %s (%s), coordinates unchanged\n",
                   addresses[i], en.city, zh.city, zh.countryName);
        }
        linkatlasGeoClose(reader);
        unlink(database);
        unlink(table);
    }
    rmdir(directory);
    puts("geo tests passed");
    return 0;
}
