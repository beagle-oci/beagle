#!/bin/sh
# Run all tests with cross-package coverage and print a per-package summary.
#
#   sh hack/coverage.sh            # plain text
#   sh hack/coverage.sh markdown   # Markdown table (used for the CI summary)
#
# Test output goes to stderr, the summary to stdout. Coverage counts code
# exercised by any test (e.g. internal/oci via the UI tests); test helpers
# (ocitest) and dev tools (hack/) are excluded. The profile is written to
# $COVERPROFILE (default coverage.out) for `go tool cover -html`.
set -eu

format="${1:-text}"
profile="${COVERPROFILE:-coverage.out}"
module="$(go list -m)"

go test -count=1 -coverpkg=./... -coverprofile="$profile.raw" ./... 1>&2
grep -v -E '/(hack|ocitest)/' "$profile.raw" >"$profile"
rm -f "$profile.raw"

awk -v module="$module/" '
NR == 1 { next } # mode line
{
	split($1, loc, ":")
	pkg = loc[1]
	sub(/\/[^\/]*$/, "", pkg)
	sub(module, "", pkg)
	# The same block appears once per test binary; count it once and treat
	# it as covered if any binary covered it.
	stmts[$1] = $2
	owner[$1] = pkg
	if ($3 > 0) hit[$1] = 1
}
END {
	for (b in stmts) {
		total[owner[b]] += stmts[b]
		all += stmts[b]
		if (b in hit) {
			covered[owner[b]] += stmts[b]
			allCovered += stmts[b]
		}
	}
	for (p in total) printf "%s %.1f\n", p, 100 * covered[p] / total[p]
	printf "~total %.1f\n", (all ? 100 * allCovered / all : 0)
}' "$profile" | sort | {
	if [ "$format" = "markdown" ]; then
		echo "### Test coverage"
		echo
		echo "| Package | Coverage |"
		echo "| --- | ---: |"
		while read -r pkg pct; do
			if [ "$pkg" = "~total" ]; then
				echo "| **total** | **$pct %** |"
			else
				echo "| \`$pkg\` | $pct % |"
			fi
		done
	else
		while read -r pkg pct; do
			[ "$pkg" = "~total" ] && pkg="total"
			printf '%-24s %6s %%\n' "$pkg" "$pct"
		done
	fi
}
