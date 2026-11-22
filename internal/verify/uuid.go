package verify

import "regexp"

// uuidPattern matches the canonical 8-4-4-4-12 hyphenated UUID textual
// form. Hex digits may be any case per RFC 4122; architecture doc section
// 7.4 step 6 requires an exact, case-sensitive string compare for the
// membership test itself, which happens separately after format validation.
var uuidPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

func validUUID(s string) bool {
	return uuidPattern.MatchString(s)
}
