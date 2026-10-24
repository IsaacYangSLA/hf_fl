package schema

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

const frozenPython311RegexCorpus = `[{"pattern": "", "value": "", "compile": true, "match": true}, {"pattern": "a", "value": "ba", "compile": true, "match": true}, {"pattern": "^a$", "value": "a", "compile": true, "match": true}, {"pattern": "^a$", "value": "a\n", "compile": true, "match": true}, {"pattern": "^a\\Z", "value": "a\n", "compile": true, "match": false}, {"pattern": "^a\\Z", "value": "a", "compile": true, "match": true}, {"pattern": "^\\w+$", "value": "é", "compile": true, "match": true}, {"pattern": "^\\w+$", "value": "²", "compile": true, "match": true}, {"pattern": "^\\w+$", "value": "́", "compile": true, "match": false}, {"pattern": "^\\w+$", "value": "𐐀", "compile": true, "match": true}, {"pattern": "^\\w+$", "value": "😀", "compile": true, "match": false}, {"pattern": "^\\d+$", "value": "١", "compile": true, "match": true}, {"pattern": "^\\d+$", "value": "²", "compile": true, "match": false}, {"pattern": "^\\s+$", "value": "\u001c", "compile": true, "match": true}, {"pattern": "^\\s+$", "value": " ", "compile": true, "match": true}, {"pattern": "^\\s+$", "value": "​", "compile": true, "match": false}, {"pattern": "^\\W+$", "value": "́", "compile": true, "match": true}, {"pattern": "^\\W+$", "value": "²", "compile": true, "match": false}, {"pattern": "^\\D+$", "value": "²", "compile": true, "match": true}, {"pattern": "^\\S+$", "value": "\u001c", "compile": true, "match": false}, {"pattern": "\\b²\\b", "value": "²", "compile": true, "match": true}, {"pattern": "\\bé\\b", "value": "é", "compile": true, "match": true}, {"pattern": "\\bé\\b", "value": "aé", "compile": true, "match": false}, {"pattern": "\\B", "value": "", "compile": true, "match": false}, {"pattern": "a\\Bb", "value": "ab", "compile": true, "match": true}, {"pattern": "a\\bb", "value": "ab", "compile": true, "match": false}, {"pattern": "(?P<word>a)(?P=word)", "value": "aa", "compile": true, "match": true}, {"pattern": "(?P<word>a)(?P=word)", "value": "ab", "compile": true, "match": false}, {"pattern": "(a)(?P<n>b)(c)\\1(?P=n)\\3", "value": "abcabc", "compile": true, "match": true}, {"pattern": "(?P<n>a)(b)\\1\\2", "value": "abab", "compile": true, "match": true}, {"pattern": "(a)(?P<n>b)\\2", "value": "abb", "compile": true, "match": true}, {"pattern": "(?P<q>['\"])(.*?)(?P=q)", "value": "\"value\"", "compile": true, "match": true}, {"pattern": "(?P<q>['\"])(.*?)(?P=q)", "value": "\"value'", "compile": true, "match": false}, {"pattern": "(?<=a)b", "value": "ab", "compile": true, "match": true}, {"pattern": "(?<!a)b", "value": "cb", "compile": true, "match": true}, {"pattern": "(?<!a)b", "value": "ab", "compile": true, "match": false}, {"pattern": "(?<=a{2})b", "value": "aab", "compile": true, "match": true}, {"pattern": "(?<=a+)b", "value": "aab", "compile": false, "match": false}, {"pattern": "(?<=(a)\\1)b", "value": "aab", "compile": false, "match": false}, {"pattern": "(a)(?<=\\1)b", "value": "ab", "compile": true, "match": true}, {"pattern": "a(?=b)", "value": "ab", "compile": true, "match": true}, {"pattern": "a(?!b)", "value": "ac", "compile": true, "match": true}, {"pattern": "a(?!b)", "value": "ab", "compile": true, "match": false}, {"pattern": "(?=a)+", "value": "a", "compile": true, "match": true}, {"pattern": "(a)?(?(1)b|c)", "value": "ab", "compile": true, "match": true}, {"pattern": "(a)?(?(1)b|c)", "value": "c", "compile": true, "match": true}, {"pattern": "(a)?(?(1)b|c)", "value": "ac", "compile": true, "match": true}, {"pattern": "(?P<x>a)?(?(x)b|c)", "value": "ab", "compile": true, "match": true}, {"pattern": "(?(1)a|b)(c)", "value": "bc", "compile": true, "match": true}, {"pattern": "(?(missing)a|b)", "value": "b", "compile": false, "match": false}, {"pattern": "(a)(?(1)b|c|d)", "value": "ab", "compile": false, "match": false}, {"pattern": "(?P<x>(?P=x))", "value": "a", "compile": false, "match": false}, {"pattern": "(?P<x>a)(?P<x>b)", "value": "ab", "compile": false, "match": false}, {"pattern": "a++a", "value": "aa", "compile": true, "match": false}, {"pattern": "a+a", "value": "aa", "compile": true, "match": true}, {"pattern": "a*+a", "value": "aa", "compile": true, "match": false}, {"pattern": "a?+a", "value": "a", "compile": true, "match": false}, {"pattern": "a{1,2}+a", "value": "aa", "compile": true, "match": false}, {"pattern": "a{1,2}a", "value": "aa", "compile": true, "match": true}, {"pattern": "(?>a+)a", "value": "aa", "compile": true, "match": false}, {"pattern": "^a{,2}$", "value": "aaa", "compile": true, "match": false}, {"pattern": "^a{,2}$", "value": "aa", "compile": true, "match": true}, {"pattern": "^a{,}$", "value": "aaa", "compile": true, "match": true}, {"pattern": "a{2,1}", "value": "aa", "compile": false, "match": false}, {"pattern": "a{abc}", "value": "a{abc}", "compile": true, "match": true}, {"pattern": "{2}", "value": "aa", "compile": false, "match": false}, {"pattern": "a**", "value": "aa", "compile": false, "match": false}, {"pattern": "(?x) a # comment\n b", "value": "ab", "compile": true, "match": true}, {"pattern": "(?x)[ #]+", "value": " #", "compile": true, "match": true}, {"pattern": "(?x)a\\ b", "value": "a b", "compile": true, "match": true}, {"pattern": "a (?x)b", "value": "a b", "compile": false, "match": false}, {"pattern": "(?i)a", "value": "A", "compile": true, "match": true}, {"pattern": "(?i:a)(?-i:b)", "value": "Ab", "compile": true, "match": true}, {"pattern": "(?i:a)(?-i:b)", "value": "AB", "compile": true, "match": false}, {"pattern": "(?a:^\\w+$)", "value": "é", "compile": true, "match": false}, {"pattern": "(?u:^\\w+$)", "value": "é", "compile": true, "match": true}, {"pattern": "(?a:\\w+)-(?u:\\w+)", "value": "abc-é", "compile": true, "match": true}, {"pattern": "(?a:\\w+)-(?u:\\w+)", "value": "é-é", "compile": true, "match": false}, {"pattern": "(?s)^a.b$", "value": "a\nb", "compile": true, "match": true}, {"pattern": "(?m)^b$", "value": "a\nb\nc", "compile": true, "match": true}, {"pattern": "(?i)^[a-z]+$", "value": "İıſK", "compile": true, "match": true}, {"pattern": "(?ai)^[a-z]+$", "value": "İ", "compile": true, "match": false}, {"pattern": "(?ai)^[a-z]+$", "value": "ASCII", "compile": true, "match": true}, {"pattern": "(?i)^i$", "value": "ı", "compile": true, "match": true}, {"pattern": "(?i)^i$", "value": "İ", "compile": true, "match": true}, {"pattern": "(?i)^k$", "value": "K", "compile": true, "match": true}, {"pattern": "(?i)^s$", "value": "ſ", "compile": true, "match": true}, {"pattern": "^\\U0001F600$", "value": "😀", "compile": true, "match": true}, {"pattern": "^\\u00e9$", "value": "é", "compile": true, "match": true}, {"pattern": "^\\x61$", "value": "a", "compile": true, "match": true}, {"pattern": "^\\141$", "value": "a", "compile": true, "match": true}, {"pattern": "^\\08$", "value": "\u00008", "compile": true, "match": true}, {"pattern": "^[\\w-]+$", "value": "é-²", "compile": true, "match": true}, {"pattern": "^[^\\w]+$", "value": "́", "compile": true, "match": true}, {"pattern": "^[\\W\\d]+$", "value": "😀١", "compile": true, "match": true}, {"pattern": "^[a-z\\W]+$", "value": "abc😀", "compile": true, "match": true}, {"pattern": "^[a-\\w]$", "value": "a", "compile": false, "match": false}, {"pattern": "^[\\b]$", "value": "\b", "compile": true, "match": true}, {"pattern": "[]]", "value": "a]", "compile": true, "match": true}, {"pattern": "[[]", "value": "[", "compile": true, "match": true}, {"pattern": "[-a]", "value": "-", "compile": true, "match": true}, {"pattern": "[a-]", "value": "-", "compile": true, "match": true}, {"pattern": "[^]]+", "value": "abc", "compile": true, "match": true}, {"pattern": "[", "value": "a", "compile": false, "match": false}, {"pattern": "[]", "value": "a", "compile": false, "match": false}, {"pattern": "\\p{L}", "value": "é", "compile": false, "match": false}, {"pattern": "(?<word>a)", "value": "a", "compile": false, "match": false}, {"pattern": "(?n)a", "value": "a", "compile": false, "match": false}, {"pattern": "(?L)a", "value": "a", "compile": false, "match": false}, {"pattern": "(?i-i:a)", "value": "a", "compile": false, "match": false}, {"pattern": "(?au:a)", "value": "a", "compile": false, "match": false}, {"pattern": "\\8", "value": "8", "compile": false, "match": false}, {"pattern": "a\\z", "value": "a", "compile": false, "match": false, "unsupported": "python314_end_anchor"}, {"pattern": "\\N{LATIN SMALL LETTER E WITH ACUTE}", "value": "é", "compile": true, "match": true, "unsupported": "unicode_name_escape"}, {"pattern": "(?ai)(a)\\1", "value": "aa", "compile": true, "match": true, "unsupported": "casefold_backreference"}, {"pattern": "(?P<π>a)(?P=π)", "value": "aa", "compile": true, "match": true, "unsupported": "unicode_capture_name"}, {"pattern": "a{2147483648}", "value": "a", "compile": true, "match": false, "unsupported": "large_repeat"}, {"pattern": "(?i)^i$", "value": "ı", "compile": true, "match": true}, {"pattern": "(?i)^s$", "value": "ſ", "compile": true, "match": true}, {"pattern": "(?i)^µ$", "value": "μ", "compile": true, "match": true}, {"pattern": "(?i)^ı$", "value": "i", "compile": true, "match": true}, {"pattern": "(?i)^ſ$", "value": "s", "compile": true, "match": true}, {"pattern": "(?i)^ͅ$", "value": "ι", "compile": true, "match": true}, {"pattern": "(?i)^ͅ$", "value": "ι", "compile": true, "match": true}, {"pattern": "(?i)^ΐ$", "value": "ΐ", "compile": true, "match": true}, {"pattern": "(?i)^ΰ$", "value": "ΰ", "compile": true, "match": true}, {"pattern": "(?i)^β$", "value": "ϐ", "compile": true, "match": true}, {"pattern": "(?i)^ε$", "value": "ϵ", "compile": true, "match": true}, {"pattern": "(?i)^θ$", "value": "ϑ", "compile": true, "match": true}, {"pattern": "(?i)^ι$", "value": "ͅ", "compile": true, "match": true}, {"pattern": "(?i)^ι$", "value": "ι", "compile": true, "match": true}, {"pattern": "(?i)^κ$", "value": "ϰ", "compile": true, "match": true}, {"pattern": "(?i)^μ$", "value": "µ", "compile": true, "match": true}, {"pattern": "(?i)^π$", "value": "ϖ", "compile": true, "match": true}, {"pattern": "(?i)^ρ$", "value": "ϱ", "compile": true, "match": true}, {"pattern": "(?i)^ς$", "value": "σ", "compile": true, "match": true}, {"pattern": "(?i)^σ$", "value": "ς", "compile": true, "match": true}, {"pattern": "(?i)^φ$", "value": "ϕ", "compile": true, "match": true}, {"pattern": "(?i)^ϐ$", "value": "β", "compile": true, "match": true}, {"pattern": "(?i)^ϑ$", "value": "θ", "compile": true, "match": true}, {"pattern": "(?i)^ϕ$", "value": "φ", "compile": true, "match": true}, {"pattern": "(?i)^ϖ$", "value": "π", "compile": true, "match": true}, {"pattern": "(?i)^ϰ$", "value": "κ", "compile": true, "match": true}, {"pattern": "(?i)^ϱ$", "value": "ρ", "compile": true, "match": true}, {"pattern": "(?i)^ϵ$", "value": "ε", "compile": true, "match": true}, {"pattern": "(?i)^в$", "value": "ᲀ", "compile": true, "match": true}, {"pattern": "(?i)^д$", "value": "ᲁ", "compile": true, "match": true}, {"pattern": "(?i)^о$", "value": "ᲂ", "compile": true, "match": true}, {"pattern": "(?i)^с$", "value": "ᲃ", "compile": true, "match": true}, {"pattern": "(?i)^т$", "value": "ᲄ", "compile": true, "match": true}, {"pattern": "(?i)^т$", "value": "ᲅ", "compile": true, "match": true}, {"pattern": "(?i)^ъ$", "value": "ᲆ", "compile": true, "match": true}, {"pattern": "(?i)^ѣ$", "value": "ᲇ", "compile": true, "match": true}, {"pattern": "(?i)^ᲀ$", "value": "в", "compile": true, "match": true}, {"pattern": "(?i)^ᲁ$", "value": "д", "compile": true, "match": true}, {"pattern": "(?i)^ᲂ$", "value": "о", "compile": true, "match": true}, {"pattern": "(?i)^ᲃ$", "value": "с", "compile": true, "match": true}, {"pattern": "(?i)^ᲄ$", "value": "т", "compile": true, "match": true}, {"pattern": "(?i)^ᲄ$", "value": "ᲅ", "compile": true, "match": true}, {"pattern": "(?i)^ᲅ$", "value": "т", "compile": true, "match": true}, {"pattern": "(?i)^ᲅ$", "value": "ᲄ", "compile": true, "match": true}, {"pattern": "(?i)^ᲆ$", "value": "ъ", "compile": true, "match": true}, {"pattern": "(?i)^ᲇ$", "value": "ѣ", "compile": true, "match": true}, {"pattern": "(?i)^ᲈ$", "value": "ꙋ", "compile": true, "match": true}, {"pattern": "(?i)^ṡ$", "value": "ẛ", "compile": true, "match": true}, {"pattern": "(?i)^ẛ$", "value": "ṡ", "compile": true, "match": true}, {"pattern": "(?i)^ι$", "value": "ͅ", "compile": true, "match": true}, {"pattern": "(?i)^ι$", "value": "ι", "compile": true, "match": true}, {"pattern": "(?i)^ΐ$", "value": "ΐ", "compile": true, "match": true}, {"pattern": "(?i)^ΰ$", "value": "ΰ", "compile": true, "match": true}, {"pattern": "(?i)^ꙋ$", "value": "ᲈ", "compile": true, "match": true}, {"pattern": "(?i)^ﬅ$", "value": "ﬆ", "compile": true, "match": true}, {"pattern": "(?i)^ﬆ$", "value": "ﬅ", "compile": true, "match": true}]`

func TestPythonRegexDifferentialCorpus(t *testing.T) {
	var cases []struct {
		Pattern     string
		Value       string
		Compile     bool
		Match       bool
		Unsupported string
	}
	if err := json.Unmarshal([]byte(frozenPython311RegexCorpus), &cases); err != nil {
		t.Fatal(err)
	}
	for i, c := range cases {
		t.Run(fmtCase(i), func(t *testing.T) {
			re, err := compileRegexp(c.Pattern)
			if c.Unsupported != "" {
				var unsupported *UnsupportedRegexError
				if !errors.As(err, &unsupported) || unsupported.Feature != c.Unsupported {
					t.Fatalf("pattern%q: expected unsupported %s, got%v", c.Pattern, c.Unsupported, err)
				}
				return
			}
			if (err == nil) != c.Compile {
				t.Fatalf("pattern%q: compile=%v expected%v error%v", c.Pattern, err == nil, c.Compile, err)
			}
			if err == nil && re.MatchString(c.Value) != c.Match {
				t.Fatalf("pattern%q value%q: match differs from Python3.11", c.Pattern, c.Value)
			}
		})
	}
}
func fmtCase(i int) string {
	const digits = "0123456789"
	return string([]byte{digits[(i/100)%10], digits[(i/10)%10], digits[i%10]})
}
func TestRegexBudgetAbortsInsteadOfReturningFalse(t *testing.T) {
	re, err := compileRegexp(`(a+)+$`)
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	defer func() {
		r := recover()
		if _, ok := r.(RegexTimeoutError); !ok {
			t.Fatalf("expected typed budget panic, got%T", r)
		}
		if time.Since(started) > 3*time.Second {
			t.Fatal("regex budget was not bounded")
		}
	}()
	re.MatchString(strings.Repeat("a", 20000) + "!")
	t.Fatal("catastrophic regex unexpectedly finished")
}

func TestRegexTranslationBounds(t *testing.T) {
	for _, c := range []struct{ pattern, feature string }{
		{strings.Repeat("(", 257) + "a" + strings.Repeat(")", 257), "regex_nesting_limit"},
		{strings.Repeat("a", 65537), "regex_source_limit"},
		{"(?ai:(a)\\1)", "casefold_backreference"},
		{strings.Repeat("\\b", 20000), "regex_expansion_limit"},
	} {
		_, err := compileRegexp(c.pattern)
		var unsupported *UnsupportedRegexError
		if !errors.As(err, &unsupported) || unsupported.Feature != c.feature {
			t.Fatalf("expected %s guard, got%v", c.feature, err)
		}
	}
}
