// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Package injection — HTML structural analysis sub-module.
//
// This file extends the injection scanner to detect payloads hidden via HTML
// structural techniques. The primary injection scanner (injection.go) runs
// regex patterns against raw text. This scanner parses HTML DOM to detect
// content that is invisible to humans but fully readable by LLMs.
//
// Active attack techniques this catches (April 2026 threat landscape):
//
//  1. CSS-hidden text:
//     - display: none / visibility: hidden
//     - font-size: 0px / 1px
//     - color matching background (near-transparent)
//     - opacity: 0
//     - position: absolute with negative offsets
//
//  2. HTML comment injection:
//     - Payloads buried inside <!-- --> comment blocks
//     - These are stripped by some scrapers but preserved by others
//
//  3. Meta tag / structured data injection:
//     - Instructions in <meta> content attributes
//     - Payloads in Open Graph (og:) tags
//     - Instructions in JSON-LD <script type="application/ld+json">
//
// Integration: called by injection.Scan() when content contains HTML tags.
// The HTML risk findings are merged into the main injection Result.
package injection

import (
	"regexp"
	"strings"

	"golang.org/x/net/html"
)

// HTMLRiskResult captures structural risks found by HTML analysis.
type HTMLRiskResult struct {
	Findings []Finding
	Score    float64 // 0.0–1.0 composite risk
}

// ── Regex patterns for CSS hiding detection ───────────────────────────────────

var cssHidePatterns = []*regexp.Regexp{
	// display: none (with optional whitespace variations)
	regexp.MustCompile(`(?i)display\s*:\s*none`),
	// visibility: hidden
	regexp.MustCompile(`(?i)visibility\s*:\s*hidden`),
	// font-size: 0 or 1px
	regexp.MustCompile(`(?i)font-size\s*:\s*[01](?:px|em|rem|pt)?(?:\s|;|")`),
	// opacity: 0
	regexp.MustCompile(`(?i)opacity\s*:\s*0(?:\.0+)?(?:\s|;|")`),
	// color with near-zero alpha: rgba(x,x,x,0) or rgba(x,x,x,0.0x)
	regexp.MustCompile(`(?i)(?:color|background)\s*:\s*rgba?\([^)]*,\s*0(?:\.0\d?)?\s*\)`),
	// position: absolute/fixed with large negative offsets (off-screen hiding)
	regexp.MustCompile(`(?i)(?:left|top)\s*:\s*-\d{4,}px`),
	// height: 0 or width: 0
	regexp.MustCompile(`(?i)(?:height|width)\s*:\s*0(?:px)?(?:\s|;|")`),
	// clip: rect(0,0,0,0) — classic screen-reader-only technique abused for hiding
	regexp.MustCompile(`(?i)clip\s*:\s*rect\(0`),
	// clip-path: inset(50%) — modern equivalent of clip:rect, used to visually
	// hide elements while keeping them in the DOM for LLMs to read
	regexp.MustCompile(`(?i)clip-path\s*:\s*inset\(\s*(?:50|100)%`),
	// overflow: hidden combined with tiny dimensions (used together to hide text)
	regexp.MustCompile(`(?i)overflow\s*:\s*hidden`),
}

// injectionLikeContent checks if text content looks like it contains prompt
// injection instructions. Used to avoid false positives on legitimate hidden
// text (e.g. screen reader labels, analytics tags).
var injectionIndicators = []*regexp.Regexp{
	regexp.MustCompile(`(?i)ignore\s+(all\s+)?previous`),
	regexp.MustCompile(`(?i)you\s+are\s+now`),
	regexp.MustCompile(`(?i)new\s+instructions?`),
	regexp.MustCompile(`(?i)system\s*:\s*`),
	regexp.MustCompile(`(?i)forget\s+(everything|all|your)`),
	regexp.MustCompile(`(?i)override\s+(your|the|all)`),
	regexp.MustCompile(`(?i)do\s+not\s+(tell|reveal|mention|say)`),
	regexp.MustCompile(`(?i)(execute|run|perform)\s+(this|the\s+following)`),
	regexp.MustCompile(`(?i)transfer\s+\$?\d+`),
	regexp.MustCompile(`(?i)send\s+(me|to)\s+(the|this|your)`),
	regexp.MustCompile(`(?i)paypal\.me`),
	regexp.MustCompile(`(?i)api[_\s]?key`),
	regexp.MustCompile(`(?i)secret[_\s]?(key|token)`),
	regexp.MustCompile(`(?i)curl\s+`),
	regexp.MustCompile(`(?i)wget\s+`),
	regexp.MustCompile(`(?i)rm\s+-rf`),
	regexp.MustCompile(`(?i)sudo\s+`),
	regexp.MustCompile(`(?i)\bexfiltrate\b`),
	regexp.MustCompile(`(?i)\bbase64\s+encode\b`),
}

// ScanHTML parses HTML content and examines the DOM structure for hidden
// injection payloads. Returns findings for any hidden text that contains
// injection-like patterns. Legitimate hidden text (screen reader labels,
// analytics fragments) is filtered out by requiring injection indicators.
func ScanHTML(content string) HTMLRiskResult {
	// Quick check: if there are no HTML tags, skip parsing entirely.
	if !strings.Contains(content, "<") {
		return HTMLRiskResult{}
	}

	var findings []Finding
	maxScore := 0.0

	// ── 1. HTML comment extraction ────────────────────────────────────────────
	// Extract text inside <!-- --> blocks and check for injection patterns.
	commentFindings := scanComments(content)
	findings = append(findings, commentFindings...)
	for _, f := range commentFindings {
		if s := severityToScore(f.Severity); s > maxScore {
			maxScore = s
		}
	}

	// ── 2. DOM parsing for CSS-hidden elements ────────────────────────────────
	doc, err := html.Parse(strings.NewReader(content))
	if err != nil {
		// Malformed HTML — not parseable. Return any comment findings we found.
		return HTMLRiskResult{Findings: findings, Score: maxScore}
	}

	hiddenFindings := walkDOM(doc)
	findings = append(findings, hiddenFindings...)
	for _, f := range hiddenFindings {
		if s := severityToScore(f.Severity); s > maxScore {
			maxScore = s
		}
	}

	// ── 3. Meta tag / structured data extraction ──────────────────────────────
	metaFindings := scanMetaTags(doc)
	findings = append(findings, metaFindings...)
	for _, f := range metaFindings {
		if s := severityToScore(f.Severity); s > maxScore {
			maxScore = s
		}
	}

	return HTMLRiskResult{Findings: findings, Score: maxScore}
}

// ── Comment scanner ───────────────────────────────────────────────────────────

var commentPattern = regexp.MustCompile(`<!--([\s\S]*?)-->`)

func scanComments(content string) []Finding {
	var findings []Finding
	matches := commentPattern.FindAllStringSubmatch(content, -1)
	for _, m := range matches {
		if len(m) < 2 {
			continue
		}
		commentText := strings.TrimSpace(m[1])
		if len(commentText) < 10 {
			continue // too short to be an injection payload
		}
		if containsInjectionIndicators(commentText) {
			findings = append(findings, Finding{
				Pattern:  "injection payload hidden in HTML comment",
				Severity: SeverityHigh,
			})
		}
	}
	return findings
}

// ── DOM walker for CSS-hidden elements ─────────────────────────────────────────

func walkDOM(n *html.Node) []Finding {
	var findings []Finding

	if n.Type == html.ElementNode {
		// Check inline style attribute for hiding patterns.
		styleAttr := getAttr(n, "style")
		if styleAttr != "" && isCSSHidden(styleAttr) {
			// Extract the text content of this hidden element.
			text := extractText(n)
			if len(text) > 10 && containsInjectionIndicators(text) {
				findings = append(findings, Finding{
					Pattern:  "injection payload in CSS-hidden element (style: " + truncate(styleAttr, 60) + ")",
					Severity: SeverityCritical,
				})
			}
		}

		// Check for hidden input fields containing injection patterns.
		if n.Data == "input" && getAttr(n, "type") == "hidden" {
			val := getAttr(n, "value")
			if containsInjectionIndicators(val) {
				findings = append(findings, Finding{
					Pattern:  "injection payload in hidden input field",
					Severity: SeverityHigh,
				})
			}
		}

		// ── aria-hidden / hidden attribute detection ──────────────────────
		// Elements with aria-hidden="true" or the HTML5 hidden attribute
		// are invisible to screen readers and often invisible to users,
		// but their text content is fully readable by LLM agents.
		// Attackers use this to inject instructions that humans cannot see.
		ariaHidden := strings.EqualFold(getAttr(n, "aria-hidden"), "true")
		htmlHidden := hasAttr(n, "hidden")
		rolePresentation := strings.EqualFold(getAttr(n, "role"), "presentation")

		if ariaHidden || htmlHidden || rolePresentation {
			text := extractText(n)
			if len(text) > 10 && containsInjectionIndicators(text) {
				attr := "aria-hidden"
				if htmlHidden {
					attr = "hidden"
				} else if rolePresentation {
					attr = "role=presentation"
				}
				findings = append(findings, Finding{
					Pattern:  "injection payload in " + attr + " element",
					Severity: SeverityCritical,
				})
			}
		}

		// ── CSS pseudo-element content scanner ──────────────────────────
		// Attackers inject payloads via CSS ::before/::after pseudo-elements
		// whose content property contains malicious instructions. These are
		// rendered by the browser but invisible in the DOM text nodes,
		// making them undetectable by standard text extraction.
		// We scan inline <style> blocks for content properties.
		if n.Data == "style" {
			findings = append(findings, scanPseudoElementContent(extractText(n))...)
		}
	}

	// Recurse into children.
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		findings = append(findings, walkDOM(c)...)
	}

	return findings
}

// ── Meta tag scanner ──────────────────────────────────────────────────────────

func scanMetaTags(doc *html.Node) []Finding {
	var findings []Finding
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode {
			switch n.Data {
			case "meta":
				// Check content attribute of meta tags for injection patterns.
				content := getAttr(n, "content")
				name := getAttr(n, "name")
				property := getAttr(n, "property")
				if content != "" && containsInjectionIndicators(content) {
					label := name
					if label == "" {
						label = property
					}
					if label == "" {
						label = "unnamed"
					}
					findings = append(findings, Finding{
						Pattern:  "injection payload in <meta " + label + "> tag",
						Severity: SeverityHigh,
					})
				}
			case "script":
				// Check JSON-LD structured data for injection patterns.
				scriptType := getAttr(n, "type")
				if scriptType == "application/ld+json" {
					text := extractText(n)
					if containsInjectionIndicators(text) {
						findings = append(findings, Finding{
							Pattern:  "injection payload in JSON-LD structured data",
							Severity: SeverityHigh,
						})
					}
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(doc)
	return findings
}

// ── Helper functions ──────────────────────────────────────────────────────────

// isCSSHidden checks if an inline style attribute contains patterns that make
// the element invisible to human readers.
func isCSSHidden(style string) bool {
	for _, p := range cssHidePatterns {
		if p.MatchString(style) {
			return true
		}
	}
	return false
}

// containsInjectionIndicators checks if text contains patterns that look like
// prompt injection instructions. This filters out false positives from
// legitimate hidden text (screen reader labels, analytics tags).
func containsInjectionIndicators(text string) bool {
	for _, p := range injectionIndicators {
		if p.MatchString(text) {
			return true
		}
	}
	return false
}

// getAttr returns the value of the named attribute on an HTML node.
func getAttr(n *html.Node, key string) string {
	for _, a := range n.Attr {
		if strings.EqualFold(a.Key, key) {
			return a.Val
		}
	}
	return ""
}

// hasAttr checks whether an HTML node has the named attribute (regardless of value).
// Used for boolean attributes like the HTML5 `hidden` attribute.
func hasAttr(n *html.Node, key string) bool {
	for _, a := range n.Attr {
		if strings.EqualFold(a.Key, key) {
			return true
		}
	}
	return false
}

// ── CSS pseudo-element scanner ────────────────────────────────────────────────
// Detects injection payloads injected via CSS ::before / ::after content
// properties inside inline <style> blocks. These are invisible in the DOM
// text tree but rendered by browsers and readable by LLM agents that
// process the raw HTML.

var pseudoContentPattern = regexp.MustCompile(`(?i)(?:::before|::after)\s*\{[^}]*content\s*:\s*["']([^"']+)["']`)

func scanPseudoElementContent(cssText string) []Finding {
	var findings []Finding
	matches := pseudoContentPattern.FindAllStringSubmatch(cssText, -1)
	for _, m := range matches {
		if len(m) < 2 {
			continue
		}
		content := m[1]
		if len(content) > 10 && containsInjectionIndicators(content) {
			findings = append(findings, Finding{
				Pattern:  "injection payload in CSS pseudo-element content (::before/::after)",
				Severity: SeverityCritical,
			})
		}
	}
	return findings
}

// extractText recursively extracts all text content from an HTML node and
// its descendants.
func extractText(n *html.Node) string {
	if n.Type == html.TextNode {
		return n.Data
	}
	var sb strings.Builder
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		sb.WriteString(extractText(c))
	}
	return sb.String()
}

// truncate cuts a string to maxLen characters, appending "..." if truncated.
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// Note: severityToScore is defined in injection.go and shared across the package.
