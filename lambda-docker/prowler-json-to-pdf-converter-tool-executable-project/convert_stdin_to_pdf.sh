#!/bin/bash
set -euo pipefail

TMP_OUTPUT_FILENAME=$(mktemp)
XETEX_OUTPUT_DIRECTORY=$(mktemp -d)
./build/prowler-to-text-report "$@" >"$TMP_OUTPUT_FILENAME"

# Yes, this is done twice on purpose
# It appears that LaTeX needs the intermediary results from the first run to get the second one right - in particular for things like the table of contents - and no, I've found no way of automatically doing this or avoiding this hilariously hacky workaround
for i in 1 2;
do
    xelatex --halt-on-error --jobname security-report --output-directory "$XETEX_OUTPUT_DIRECTORY" "$TMP_OUTPUT_FILENAME" >&2
done

rm "$TMP_OUTPUT_FILENAME"

cat "$XETEX_OUTPUT_DIRECTORY"/security-report.pdf

rm -r "$XETEX_OUTPUT_DIRECTORY"
