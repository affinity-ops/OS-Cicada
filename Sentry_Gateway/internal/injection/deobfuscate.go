// © 2026 Affinity Ops Ltd.
// SPDX-License-Identifier: Apache-2.0

package injection

import (
	"encoding/base64"
	"encoding/hex"
	"net/url"
	"regexp"
	"strings"
	"unicode"
)

var (
	// Matches candidate Base64 or Base64URL tokens of length >= 20
	base64CandidateRe = regexp.MustCompile(`[A-Za-z0-9+/_\-]{20,}={0,2}`)

	// Matches contiguous hex escapes like \x69\x67\x6e\x6f\x72\x65
	hexEscapeRe = regexp.MustCompile(`(?i)(?:\\x[0-9a-f]{2}){6,}`)

	// Matches contiguous raw hex strings of 24+ hex chars
	rawHexCandidateRe = regexp.MustCompile(`\b[0-9a-fA-F]{24,}\b`)

	// Matches single-character punctuation-separated words like "i.g.n.o.r.e" or "i-g-n-o-r-e"
	punctSplitRe    = regexp.MustCompile(`(?i)\b([a-z])(?:[.\-_+|/\\]+([a-z])){3,}\b`)
	punctSplitSepRe = regexp.MustCompile(`[.\-_+|/\\]+`)

	// Matches single-character space-separated words like "i g n o r e"
	spaceSplitRe    = regexp.MustCompile(`(?i)\b([a-z])(?:[ \t]+([a-z])){4,}\b`)
	spaceSplitSepRe = regexp.MustCompile(`[ \t]+`)
)

// homoglyphMap maps Cyrillic, Greek, and common confusable runes to canonical ASCII.
var homoglyphMap = map[rune]rune{
	// Cyrillic lowercase & uppercase confusables
	'а': 'a', 'А': 'a',
	'в': 'b', 'В': 'b',
	'с': 'c', 'С': 'c',
	'е': 'e', 'Е': 'e',
	'н': 'h', 'Н': 'h',
	'і': 'i', 'І': 'i',
	'ї': 'i', 'Ї': 'i',
	'ј': 'j', 'Ј': 'j',
	'к': 'k', 'К': 'k',
	'м': 'm', 'М': 'm',
	'о': 'o', 'О': 'o',
	'р': 'p', 'Р': 'p',
	'ѕ': 's', 'Ѕ': 's',
	'т': 't', 'Т': 't',
	'у': 'y', 'У': 'y',
	'х': 'x', 'Х': 'x',
	// Greek confusables
	'α': 'a', 'Α': 'a',
	'β': 'b', 'Β': 'b',
	'ε': 'e', 'Ε': 'e',
	'ι': 'i', 'Ι': 'i',
	'κ': 'k', 'Κ': 'k',
	'ν': 'n', 'Ν': 'n',
	'ο': 'o', 'Ο': 'o',
	'ρ': 'p', 'Ρ': 'p',
	'τ': 't', 'Τ': 't',
	'υ': 'u', 'Υ': 'u',
	'χ': 'x', 'Χ': 'x',
}

// leetWordReplacements normalizes common leetspeak evasions for high-risk injection keywords.
var leetWordReplacements = strings.NewReplacer(
	"1gn0r3", "ignore",
	"1gnor3", "ignore",
	"ign0r3", "ignore",
	"1gn0re", "ignore",
	"d1sr3g4rd", "disregard",
	"d1sregard", "disregard",
	"f0rg3t", "forget",
	"pr3v10us", "previous",
	"pr3vious", "previous",
	"1nstruct10ns", "instructions",
	"1nstruct1ons", "instructions",
	"instruct10ns", "instructions",
	"syst3m", "system",
	"pr0mpt", "prompt",
	"0v3rr1d3", "override",
	"0verr1de", "override",
	"j41lbr34k", "jailbreak",
	"j4ilbreak", "jailbreak",
	"r3str1ct10ns", "restrictions",
	"d3v3l0p3r", "developer",
)

// detectUnicodeSmuggling inspects raw text for invisible Unicode Tag characters
// (U+E0000..U+E007F, used in ASCII smuggling attacks) and Bidirectional (Bidi)
// override characters (U+202A..U+202E, U+2066..U+2069).
// It returns any structural findings plus the decoded ASCII from any tag characters.
func detectUnicodeSmuggling(body string) (findings []Finding, smuggledASCII string) {
	var tagBuilder strings.Builder
	hasBidi := false

	for _, r := range body {
		// Unicode Tag block: U+E0000 to U+E007F
		if r >= 0xE0000 && r <= 0xE007F {
			ascii := r - 0xE0000
			if ascii >= 0x20 && ascii <= 0x7E {
				tagBuilder.WriteRune(ascii)
			}
		}
		// Bidi control characters
		if (r >= 0x202A && r <= 0x202E) || (r >= 0x2066 && r <= 0x2069) {
			hasBidi = true
		}
	}

	smuggled := tagBuilder.String()
	if len(smuggled) > 0 {
		excerpt := smuggled
		if len(excerpt) > 120 {
			excerpt = excerpt[:120]
		}
		findings = append(findings, Finding{
			Pattern:  "unicode tag smuggling (invisible ASCII injection)",
			Severity: SeverityCritical,
			Excerpt:  excerpt,
		})
	}

	if hasBidi {
		findings = append(findings, Finding{
			Pattern:  "bidirectional unicode override (spoofing/injection)",
			Severity: SeverityHigh,
			Excerpt:  "bidi override control character detected",
		})
	}

	return findings, smuggled
}

// canonicalizeText strips zero-width/invisible runes, folds full-width Unicode
// and Cyrillic/Greek homoglyphs into ASCII, collapses spaced/dotted character
// splitting ("i g n o r e" -> "ignore"), and normalizes leetspeak keywords.
func canonicalizeText(s string) string {
	var b strings.Builder
	b.Grow(len(s))

	for _, r := range s {
		// Strip zero-width & invisible formatting characters
		switch r {
		case '\u200B', '\u200C', '\u200D', '\u200E', '\u200F',
			'\uFEFF', '\u2060', '\u00AD', '\u180E', '\u034F':
			continue
		}
		if r >= 0xE0000 && r <= 0xE007F {
			continue
		}
		// Fold full-width ASCII (U+FF01..U+FF5E) to standard ASCII (0x21..0x7E)
		if r >= 0xFF01 && r <= 0xFF5E {
			r = r - 0xFF01 + 0x21
		}
		// Fold confusable Cyrillic/Greek homoglyphs
		if mapped, ok := homoglyphMap[r]; ok {
			r = mapped
		}
		b.WriteRune(r)
	}

	normalized := b.String()

	// 1. Collapse punctuation-split evasions like "i.g.n.o.r.e" or "i-g-n-o-r-e" per word
	normalized = punctSplitRe.ReplaceAllStringFunc(normalized, func(match string) string {
		return punctSplitSepRe.ReplaceAllString(match, "")
	})

	// 2. Collapse space-split evasions like "i g n o r e"
	normalized = spaceSplitRe.ReplaceAllStringFunc(normalized, func(match string) string {
		collapsed := spaceSplitSepRe.ReplaceAllString(match, "")
		return resegmentCollapsedKeywords(collapsed)
	})

	// Apply leetspeak keyword normalization on lowercase copy
	lower := strings.ToLower(normalized)
	replaced := leetWordReplacements.Replace(lower)
	if replaced != lower {
		return replaced
	}

	return normalized
}

// resegmentCollapsedKeywords ensures that if multiple space-split words were
// collapsed together (e.g., "i g n o r e a l l p r e v i o u s" -> "ignoreallprevious"),
// known injection keywords are separated by spaces so standard regexes match.
var collapsedKeywordRestorer = strings.NewReplacer(
	"ignore", " ignore ",
	"disregard", " disregard ",
	"forget", " forget ",
	"previous", " previous ",
	"prior", " prior ",
	"instructions", " instructions ",
	"instruction", " instruction ",
	"system", " system ",
	"prompt", " prompt ",
	"override", " override ",
)

func resegmentCollapsedKeywords(s string) string {
	return collapsedKeywordRestorer.Replace(strings.ToLower(s))
}

// extractDecodedPayloads finds Base64, URL-encoded, Hex-escaped, and ROT13
// segments inside body so the scanner can inspect their decoded plaintext.
func extractDecodedPayloads(body string) []struct {
	encoding string
	decoded  string
} {
	var out []struct {
		encoding string
		decoded  string
	}

	// 1. URL-encoded sequences (%XX)
	if strings.Count(body, "%") >= 4 {
		if unescaped, err := url.QueryUnescape(body); err == nil && unescaped != body {
			out = append(out, struct{ encoding, decoded string }{"url_encoding", unescaped})
		}
	}

	// 2. Base64 / Base64URL candidate blobs
	matches := base64CandidateRe.FindAllString(body, 10)
	for _, m := range matches {
		if decoded, ok := tryDecodeBase64(m); ok {
			out = append(out, struct{ encoding, decoded string }{"base64", decoded})
		}
	}

	// 3. Hex-escaped sequences (\x69\x67...)
	hexMatches := hexEscapeRe.FindAllString(body, 5)
	for _, hm := range hexMatches {
		cleanHex := strings.ReplaceAll(strings.ToLower(hm), `\x`, "")
		if raw, err := hex.DecodeString(cleanHex); err == nil && isMostlyPrintable(raw) {
			out = append(out, struct{ encoding, decoded string }{"hex_escape", string(raw)})
		}
	}

	// 4. Raw hex blobs (48+ hex chars)
	rawHexMatches := rawHexCandidateRe.FindAllString(body, 5)
	for _, rhm := range rawHexMatches {
		if len(rhm)%2 == 0 {
			if raw, err := hex.DecodeString(rhm); err == nil && isMostlyPrintable(raw) {
				out = append(out, struct{ encoding, decoded string }{"hex", string(raw)})
			}
		}
	}

	// 5. ROT13 decoding if ROT13/caesar is mentioned OR if body contains classic ROT13 trigger tokens
	lower := strings.ToLower(body)
	if strings.Contains(lower, "rot13") || strings.Contains(lower, "caesar") ||
		strings.Contains(lower, "vtaber") || strings.Contains(lower, "qvfertneq") ||
		strings.Contains(lower, "flfgrz cebzcg") {
		out = append(out, struct{ encoding, decoded string }{"rot13", rot13(body)})
	}

	return out
}

func tryDecodeBase64(s string) (string, bool) {
	trimmed := strings.TrimRight(s, "=")
	if len(trimmed) < 16 {
		return "", false
	}
	encodings := []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	}
	for _, enc := range encodings {
		if raw, err := enc.DecodeString(s); err == nil && len(raw) >= 12 && isMostlyPrintable(raw) {
			return string(raw), true
		}
		if raw, err := enc.DecodeString(trimmed); err == nil && len(raw) >= 12 && isMostlyPrintable(raw) {
			return string(raw), true
		}
	}
	return "", false
}

func isMostlyPrintable(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	printable := 0
	for _, b := range data {
		if (b >= 0x20 && b <= 0x7E) || b == '\n' || b == '\r' || b == '\t' {
			printable++
		} else if b == 0 {
			return false
		}
	}
	return float64(printable)/float64(len(data)) >= 0.85
}

func rot13(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z':
			return 'a' + (r-'a'+13)%26
		case r >= 'A' && r <= 'Z':
			return 'A' + (r-'A'+13)%26
		default:
			_ = unicode.IsLetter
			return r
		}
	}, s)
}
