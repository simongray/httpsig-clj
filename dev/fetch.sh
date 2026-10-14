#!/bin/sh
# Download the tests of structured fields at the version that the library
# follows into dev-resources/.
set -eu

sft=781ba38464b2ec4c547e1e14d007d4f5ace7457e

cd "$(dirname "$0")/.."
mkdir -p dev-resources/structured-field-tests/serialisation-tests

for f in binary.json boolean.json date.json dictionary.json display-string.json \
         examples.json item.json key-generated.json large-generated.json \
         list.json listlist.json number-generated.json number.json \
         param-dict.json param-list.json param-listlist.json \
         string-generated.json string.json token-generated.json token.json \
         serialisation-tests/key-generated.json serialisation-tests/number.json \
         serialisation-tests/string-generated.json \
         serialisation-tests/token-generated.json; do
  curl -sSfL -o "dev-resources/structured-field-tests/$f" \
    "https://raw.githubusercontent.com/httpwg/structured-field-tests/$sft/$f"
done
