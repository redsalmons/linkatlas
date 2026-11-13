# Offline city names

`data/city-names.tsv` supplements missing city-name translations in DB-IP Lite.
It is derived from GeoNames `cities5000.zip` and `alternateNamesV2.zip`:

- https://download.geonames.org/export/dump/cities5000.zip
- https://download.geonames.org/export/dump/alternateNamesV2.zip
- Attribution: **City names by GeoNames**, https://www.geonames.org/
- License: **Creative Commons Attribution 4.0 International**,
  https://creativecommons.org/licenses/by/4.0/

The derived file selects contemporary translated names and English/canonical
aliases, normalizes ASCII case, and sorts records for local binary searches.
It contains no IP addresses and never changes the coordinates from DB-IP.
Matching requires the same country and city name, with the nearest namesake
within 50 km of the DB-IP coordinates. Missing translations keep the DB-IP
fallback. The unmodified DB-IP MMDB files remain separate.

Regenerate from downloaded source archives at the repository root:

```sh
python3 core/tools/build_city_names.py cities5000.zip alternateNamesV2.zip \
  third_party/geoip/data/city-names.tsv
```

The generated TSV is bundled by both platforms. Android copies it alongside its
MMDB on the first database open of each process; iOS opens the bundle resource.
Source archives and generation tools are not packaged in the apps.

Run host-side matching tests:

```sh
cmake -S core -B /tmp/linkatlas-geo-tests
cmake --build /tmp/linkatlas-geo-tests --target geo_test
ctest --test-dir /tmp/linkatlas-geo-tests -R geo_test --output-on-failure
```

The test executable also accepts a real city MMDB and the generated TSV as two
arguments to verify that translations change the labels, not the coordinates.
