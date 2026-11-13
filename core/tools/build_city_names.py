#!/usr/bin/env python3
"""Build the offline city-name supplement from unmodified GeoNames dumps.

Usage: build_city_names.py cities5000.zip alternateNamesV2.zip output.tsv
Source: https://download.geonames.org/export/dump/ (CC BY 4.0).
Only names are used at runtime; DB-IP's coordinates remain unchanged.
"""
import argparse
import io
from pathlib import Path
import zipfile


LANGUAGES = {
    "de": "de", "es": "es", "fr": "fr", "ja": "ja", "ko": "ko",
    "fa": "fa", "ru": "ru", "pt": "pt-BR", "pt-BR": "pt-BR",
    "zh": "zh-CN", "zh-CN": "zh-CN", "zh-Hans": "zh-CN",
}
ASCII_LOWER = str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz")


def rows(archive, member):
    with zipfile.ZipFile(archive) as source:
        with source.open(member) as stream:
            for line in io.TextIOWrapper(stream, encoding="utf-8"):
                yield line.rstrip("\r\n").split("\t")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("cities")
    parser.add_argument("alternate_names")
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    cities = {}
    for row in rows(args.cities, "cities5000.txt"):
        if len(row) < 19 or row[6] != "P":
            continue
        cities[row[0]] = {
            "country": row[8], "latitude": row[4], "longitude": row[5],
            "aliases": {row[1], row[2]}, "names": {},
        }
    for row in rows(args.alternate_names, "alternateNamesV2.txt"):
        if len(row) < 8 or row[1] not in cities or row[6] == "1" or row[7] == "1":
            continue
        city = cities[row[1]]
        if row[2] == "en":
            city["aliases"].add(row[3])
        language = LANGUAGES.get(row[2])
        if language is None:
            continue
        # Prefer explicit language/script, then preferred/short contemporary
        # names. IDs break ties reproducibly without relying on dump ordering.
        rank = (row[2] == language or row[2] == "zh-Hans", row[4] == "1",
                row[5] == "1", -int(row[0]))
        previous = city["names"].get(language)
        if previous is None or rank > previous[0]:
            city["names"][language] = (rank, row[3])

    records = set()
    for city in cities.values():
        for alias in city["aliases"]:
            if not alias or "|" in alias:
                continue
            alias = alias.translate(ASCII_LOWER)
            for language, (_, name) in city["names"].items():
                # One searchable key per country, original name and language.
                key = "|".join((city["country"], alias, language))
                records.add((key, city["latitude"], city["longitude"], name))
    with args.output.open("w", encoding="utf-8", newline="\n") as output:
        output.write("# GeoNames city names, CC BY 4.0; format 1\n")
        for record in sorted(records):
            if any("\t" in field or "\n" in field for field in record):
                raise ValueError("unexpected delimiter in GeoNames record")
            output.write("\t".join(record) + "\n")
    print(f"{len(records)} localized aliases from {len(cities)} cities; "
          f"{args.output.stat().st_size:,} bytes")


if __name__ == "__main__":
    main()
