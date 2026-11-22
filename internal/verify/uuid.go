package verify

import "regexp"

// uuidPattern matches the canonical 8-4-4-4-12 hyphenated UUID textual
// form, lowercase hex only. RFC 4122 permits either case, but step 1
// review A7 requires lowercase canonical form for both the local host UUID
// and every entry in a bundle's target list: without a single canonical
// form, two UUID strings that are the "same" host could fail the exact,
// case-sensitive membership compare architecture doc section 7.4 step 6
// requires, or worse, be made to look different to a human reviewer while
// comparing equal.
var uuidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func validUUID(s string) bool {
	return uuidPattern.MatchString(s)
}
