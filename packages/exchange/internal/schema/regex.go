package schema

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/dlclark/regexp2"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

// Patterns in the reference service are Python string regular expressions.
// Translate their syntax explicitly instead of silently treating them as RE2
// or .NET patterns. The matcher remains a bounded, mature regex engine.
type pythonRegexp struct {
	source string
	re     *regexp2.Regexp
}

func (r *pythonRegexp) String() string { return r.source }
func (r *pythonRegexp) MatchString(s string) bool {
	ok, err := r.re.MatchString(s)
	if err != nil {
		panic(RegexTimeoutError{})
	}
	return ok
}

// UnsupportedRegexError identifies an explicit portability boundary. Feature
// values are fixed names; pattern text is never returned to a client.
type UnsupportedRegexError struct{ Feature string }

func (e *UnsupportedRegexError) Error() string {
	return "unsupported regular expression feature: " + e.Feature
}

// RegexTimeoutError aborts the entire JSON Schema evaluation. Returning false
// would be unsafe: a surrounding not/if/oneOf could invert that result.
type RegexTimeoutError struct{}

func (RegexTimeoutError) Error() string { return "regular expression execution limit reached" }

func compileRegexp(pattern string) (jsonschema.Regexp, error) {
	if len(pattern) > 65536 {
		return nil, &UnsupportedRegexError{Feature: "regex_source_limit"}
	}
	if !utf8.ValidString(pattern) {
		return nil, fmt.Errorf("invalid regular expression")
	}
	p := regexParser{input: []rune(pattern), names: map[string]int{}, captures: []regexCapture{{}}, flags: regexFlags{}}
	n, _, err := p.expression(false, true)
	if err != nil {
		return nil, err
	}
	if p.pos != len(p.input) {
		return nil, regexSyntaxError()
	}
	for _, id := range p.conditionals {
		if id < 1 || id >= len(p.captures) {
			return nil, fmt.Errorf("invalid regular expression")
		}
	}
	re, err := regexp2.Compile(n.text, regexp2.None)
	if err != nil {
		return nil, fmt.Errorf("invalid regular expression")
	}
	// Timeouts abort the complete schema evaluation through a typed panic;
	// the schema boundary converts it to a safe failure.
	re.MatchTimeout = 100 * time.Millisecond
	return &pythonRegexp{source: pattern, re: re}, nil
}

type regexFlags struct{ ignoreCase, multiline, dotall, verbose, ascii bool }
type regexNode struct {
	text       string
	min, max   int64 // -1 means unbounded.
	repeatable bool
}
type regexCapture struct {
	width regexNode
	open  bool
}
type regexParser struct {
	input        []rune
	pos          int
	flags        regexFlags
	names        map[string]int
	captures     []regexCapture
	conditionals []int
	started      bool
	lookbehind   int
	depth        int
}

func regexSyntaxError() error { return fmt.Errorf("invalid regular expression") }
func regexName(id int) string { return fmt.Sprintf("hf2lPyCapture%d", id) }
func regexAdd(a, b int64) int64 {
	if a < 0 || b < 0 || a > (1<<62)-b {
		return -1
	}
	return a + b
}
func regexMul(a, b int64) int64 {
	if a == 0 || b == 0 {
		return 0
	}
	if a < 0 || b < 0 || a > (1<<62)/b {
		return -1
	}
	return a * b
}
func (p *regexParser) skip() {
	if !p.flags.verbose {
		return
	}
	for p.pos < len(p.input) {
		r := p.input[p.pos]
		if strings.ContainsRune(" \t\n\r\v\f", r) {
			p.pos++
			continue
		}
		if r == '#' {
			for p.pos < len(p.input) && p.input[p.pos] != '\n' {
				p.pos++
			}
			continue
		}
		break
	}
}
func (p *regexParser) expression(inGroup, top bool) (regexNode, int, error) {
	var alternatives []regexNode
	for {
		n, err := p.sequence(inGroup, top)
		if err != nil {
			return regexNode{}, 0, err
		}
		alternatives = append(alternatives, n)
		if p.pos >= len(p.input) || p.input[p.pos] != '|' {
			break
		}
		p.pos++
		p.started = true
	}
	if len(alternatives) == 1 {
		return alternatives[0], 1, nil
	}
	parts := make([]string, len(alternatives))
	out := regexNode{min: alternatives[0].min, max: alternatives[0].max, repeatable: true}
	for i, n := range alternatives {
		parts[i] = n.text
		if n.min < out.min {
			out.min = n.min
		}
		if out.max < 0 || n.max < 0 {
			out.max = -1
		} else if n.max > out.max {
			out.max = n.max
		}
	}
	out.text = strings.Join(parts, "|")
	return out, len(parts), nil
}
func (p *regexParser) sequence(inGroup, top bool) (regexNode, error) {
	out := regexNode{repeatable: true}
	var text strings.Builder
	for {
		p.skip()
		if p.pos >= len(p.input) || p.input[p.pos] == '|' || (inGroup && p.input[p.pos] == ')') {
			out.text = text.String()
			return out, nil
		}
		if p.input[p.pos] == ')' {
			return regexNode{}, regexSyntaxError()
		}
		n, empty, err := p.atom(top)
		if err != nil {
			return regexNode{}, err
		}
		if empty {
			continue
		}
		p.started = true
		p.skip()
		n, err = p.quantify(n)
		if err != nil {
			return regexNode{}, err
		}
		if text.Len()+len(n.text) > 1<<20 {
			return regexNode{}, &UnsupportedRegexError{Feature: "regex_expansion_limit"}
		}
		text.WriteString(n.text)
		out.min = regexAdd(out.min, n.min)
		out.max = regexAdd(out.max, n.max)
	}
}
func (p *regexParser) literal(r rune) regexNode {
	s := regexp2.Escape(string(r))
	if p.flags.ignoreCase {
		if p.flags.ascii {
			if r >= 'a' && r <= 'z' {
				s = "[" + string(r) + string(r-'a'+'A') + "]"
			}
			if r >= 'A' && r <= 'Z' {
				s = "[" + string(r) + string(r-'A'+'a') + "]"
			}
		} else {
			s = unicodeCaseLiteral(r)
		}
	}
	return regexNode{text: s, min: 1, max: 1, repeatable: true}
}
func (p *regexParser) atom(top bool) (regexNode, bool, error) {
	r := p.input[p.pos]
	p.pos++
	switch r {
	case '(':
		return p.group(top)
	case '[':
		n, e := p.characterClass()
		return n, false, e
	case '\\':
		n, e := p.escape(false)
		return n, false, e
	case '.':
		s := "."
		if p.flags.dotall {
			s = "(?s:.)"
		}
		return regexNode{text: s, min: 1, max: 1, repeatable: true}, false, nil
	case '^', '$':
		s := string(r)
		if p.flags.multiline {
			s = "(?m:" + s + ")"
		}
		return regexNode{text: s}, false, nil
	case '*', '+', '?':
		return regexNode{}, false, regexSyntaxError()
	case '{':
		// A syntactically valid repeat has no preceding atom here.
		start := p.pos - 1
		if _, _, _, ok, e := p.repeatBounds(start); ok || e != nil {
			return regexNode{}, false, regexSyntaxError()
		}
		return p.literal(r), false, nil
	default:
		return p.literal(r), false, nil
	}
}

func (p *regexParser) group(top bool) (regexNode, bool, error) {
	p.depth++
	defer func() { p.depth-- }()
	if p.depth > 256 {
		return regexNode{}, false, &UnsupportedRegexError{Feature: "regex_nesting_limit"}
	}
	prefix := ""
	capture := 0
	atomic := false
	assertion := false
	behind := false
	condition := 0
	oldFlags := p.flags
	oldBehind := p.lookbehind
	if p.pos < len(p.input) && p.input[p.pos] == '?' {
		p.pos++
		if p.pos >= len(p.input) {
			return regexNode{}, false, regexSyntaxError()
		}
		switch p.input[p.pos] {
		case '#':
			p.pos++
			for p.pos < len(p.input) {
				r := p.input[p.pos]
				p.pos++
				if r == '\\' && p.pos < len(p.input) {
					p.pos++
					continue
				}
				if r == ')' {
					return regexNode{}, true, nil
				}
			}
			return regexNode{}, false, regexSyntaxError()
		case ':':
			p.pos++
			prefix = "?:"
		case '>':
			p.pos++
			atomic = true
		case '=', '!':
			prefix = "?" + string(p.input[p.pos])
			p.pos++
			assertion = true
		case '<':
			p.pos++
			if p.pos >= len(p.input) || (p.input[p.pos] != '=' && p.input[p.pos] != '!') {
				return regexNode{}, false, regexSyntaxError()
			}
			prefix = "?<" + string(p.input[p.pos])
			p.pos++
			assertion = true
			behind = true
			p.lookbehind = len(p.captures)
		case 'P':
			p.pos++
			if p.pos >= len(p.input) {
				return regexNode{}, false, regexSyntaxError()
			}
			switch p.input[p.pos] {
			case '=':
				p.pos++
				name, e := p.until(')')
				if e != nil {
					return regexNode{}, false, e
				}
				id, ok := p.names[name]
				if !ok {
					return regexNode{}, false, regexSyntaxError()
				}
				n, e := p.backref(id)
				return n, false, e
			case '<':
				p.pos++
				name, e := p.until('>')
				if !asciiRegexName(name) {
					return regexNode{}, false, &UnsupportedRegexError{Feature: "unicode_capture_name"}
				}
				if e != nil || !pythonGroupName(name) {
					return regexNode{}, false, regexSyntaxError()
				}
				if _, exists := p.names[name]; exists {
					return regexNode{}, false, regexSyntaxError()
				}
				capture = len(p.captures)
				p.names[name] = capture
			default:
				return regexNode{}, false, regexSyntaxError()
			}
		case '(':
			p.pos++
			name, e := p.until(')')
			if e != nil {
				return regexNode{}, false, e
			}
			if n, e := strconv.Atoi(name); e == nil && name != "" {
				for _, r := range name {
					if r < '0' || r > '9' {
						return regexNode{}, false, regexSyntaxError()
					}
				}
				if n < 1 {
					return regexNode{}, false, regexSyntaxError()
				}
				condition = n
				p.conditionals = append(p.conditionals, n)
			} else {
				n, ok := p.names[name]
				if !ok || !pythonGroupName(name) {
					return regexNode{}, false, regexSyntaxError()
				}
				condition = n
			}
		default:
			flags, global, e := p.flagGroup()
			if e != nil {
				return regexNode{}, false, e
			}
			if global {
				if !top || p.started {
					return regexNode{}, false, regexSyntaxError()
				}
				p.flags = flags
				return regexNode{}, true, nil
			}
			p.flags = flags
			prefix = "?:"
		}
	} else {
		capture = len(p.captures)
	}
	if capture > 0 {
		p.captures = append(p.captures, regexCapture{open: true})
	}
	n, branches, e := p.expression(true, false)
	p.flags = oldFlags
	p.lookbehind = oldBehind
	if e != nil {
		return regexNode{}, false, e
	}
	if p.pos >= len(p.input) || p.input[p.pos] != ')' {
		return regexNode{}, false, regexSyntaxError()
	}
	p.pos++
	if behind && (n.max < 0 || n.min != n.max) {
		return regexNode{}, false, regexSyntaxError()
	}
	if condition > 0 && branches > 2 {
		return regexNode{}, false, regexSyntaxError()
	}
	if capture > 0 {
		p.captures[capture] = regexCapture{width: n}
		n.text = "(?<" + regexName(capture) + ">" + n.text + ")"
	} else if condition > 0 {
		n.text = "(?(" + regexName(condition) + ")" + n.text + ")"
		// Missing false branch can match empty.
		if branches == 1 {
			n.min = 0
		}
	} else if atomic {
		n.text = "(?>" + n.text + ")"
	} else {
		n.text = "(" + prefix + n.text + ")"
	}
	if assertion {
		n.min = 0
		n.max = 0
	}
	n.repeatable = true
	return n, false, nil
}
func (p *regexParser) until(end rune) (string, error) {
	start := p.pos
	for p.pos < len(p.input) && p.input[p.pos] != end {
		p.pos++
	}
	if p.pos >= len(p.input) {
		return "", regexSyntaxError()
	}
	s := string(p.input[start:p.pos])
	p.pos++
	return s, nil
}
func asciiRegexName(s string) bool {
	for _, r := range s {
		if r > 127 {
			return false
		}
	}
	return true
}
func pythonGroupName(s string) bool {
	if s == "" {
		return false
	}
	for i, r := range s {
		if i == 0 {
			if r != '_' && !unicode.IsLetter(r) && !unicode.In(r, unicode.Nl) {
				return false
			}
		} else if r != '_' && !unicode.IsLetter(r) && !unicode.IsDigit(r) && !unicode.In(r, unicode.Nl, unicode.Mn, unicode.Mc, unicode.Pc) {
			return false
		}
	}
	return true
}
func (p *regexParser) flagGroup() (regexFlags, bool, error) {
	f := p.flags
	var on, off string
	negative := false
	for p.pos < len(p.input) {
		r := p.input[p.pos]
		p.pos++
		if r == ':' || r == ')' {
			if on == "" && off == "" {
				return f, false, regexSyntaxError()
			}
			if negative && off == "" {
				return f, false, regexSyntaxError()
			}
			if r == ')' && negative {
				return f, false, regexSyntaxError()
			}
			if strings.Contains(on, "a") && strings.Contains(on, "u") {
				return f, false, regexSyntaxError()
			}
			for _, c := range on {
				if strings.ContainsRune(off, c) {
					return f, false, regexSyntaxError()
				}
			}
			for _, c := range on {
				switch c {
				case 'i':
					f.ignoreCase = true
				case 'm':
					f.multiline = true
				case 's':
					f.dotall = true
				case 'x':
					f.verbose = true
				case 'a':
					f.ascii = true
				case 'u':
					f.ascii = false
				}
			}
			for _, c := range off {
				switch c {
				case 'i':
					f.ignoreCase = false
				case 'm':
					f.multiline = false
				case 's':
					f.dotall = false
				case 'x':
					f.verbose = false
				}
			}
			return f, r == ')', nil
		}
		if r == '-' && !negative {
			negative = true
			continue
		}
		if !strings.ContainsRune("aimsux", r) || negative && strings.ContainsRune("au", r) {
			return f, false, regexSyntaxError()
		}
		if negative {
			off += string(r)
		} else {
			on += string(r)
		}
	}
	return f, false, regexSyntaxError()
}
func (p *regexParser) repeatBounds(start int) (int64, int64, int, bool, error) {
	i := start + 1
	if i >= len(p.input) {
		return 0, 0, start, false, nil
	}
	mstart := i
	for i < len(p.input) && p.input[i] >= '0' && p.input[i] <= '9' {
		i++
	}
	mtext := string(p.input[mstart:i])
	ntext := mtext
	comma := i < len(p.input) && p.input[i] == ','
	if comma {
		i++
		nstart := i
		for i < len(p.input) && p.input[i] >= '0' && p.input[i] <= '9' {
			i++
		}
		ntext = string(p.input[nstart:i])
	}
	if i >= len(p.input) || p.input[i] != '}' || (!comma && mtext == "") {
		return 0, 0, start, false, nil
	}
	m := int64(0)
	n := int64(-1)
	var e error
	if mtext != "" {
		m, e = strconv.ParseInt(mtext, 10, 32)
		if e != nil {
			return 0, 0, 0, true, &UnsupportedRegexError{Feature: "large_repeat"}
		}
	}
	if !comma {
		n = m
	} else if ntext != "" {
		n, e = strconv.ParseInt(ntext, 10, 32)
		if e != nil {
			return 0, 0, 0, true, &UnsupportedRegexError{Feature: "large_repeat"}
		}
	}
	if n >= 0 && m > n {
		return 0, 0, 0, true, regexSyntaxError()
	}
	return m, n, i + 1, true, nil
}
func (p *regexParser) quantify(n regexNode) (regexNode, error) {
	if p.pos >= len(p.input) {
		return n, nil
	}
	q := ""
	min, max := int64(0), int64(0)
	switch p.input[p.pos] {
	case '*':
		q = "*"
		min = 0
		max = -1
		p.pos++
	case '+':
		q = "+"
		min = 1
		max = -1
		p.pos++
	case '?':
		q = "?"
		min = 0
		max = 1
		p.pos++
	case '{':
		m, mx, end, ok, e := p.repeatBounds(p.pos)
		if e != nil {
			return regexNode{}, e
		}
		if !ok {
			return n, nil
		}
		if mx == m {
			q = fmt.Sprintf("{%d}", m)
		} else if mx < 0 {
			q = fmt.Sprintf("{%d,}", m)
		} else {
			q = fmt.Sprintf("{%d,%d}", m, mx)
		}
		min = m
		max = mx
		p.pos = end
	default:
		return n, nil
	}
	if !n.repeatable {
		return regexNode{}, regexSyntaxError()
	}
	lazy, possessive := false, false
	if p.pos < len(p.input) {
		if p.input[p.pos] == '?' {
			lazy = true
			p.pos++
		} else if p.input[p.pos] == '+' {
			possessive = true
			p.pos++
		}
	}
	n.text = "(?:" + n.text + ")" + q
	if lazy {
		n.text += "?"
	}
	if possessive {
		n.text = "(?>" + n.text + ")"
	}
	n.min = regexMul(n.min, min)
	n.max = regexMul(n.max, max)
	return n, nil
}
func (p *regexParser) backref(id int) (regexNode, error) {
	if id < 1 || id >= len(p.captures) || p.captures[id].open || p.lookbehind > 0 && id >= p.lookbehind {
		return regexNode{}, regexSyntaxError()
	}
	// Python case-insensitive backreferences use a different Unicode fold
	// relation from .NET. Reject instead of changing their matching semantics.
	if p.flags.ignoreCase {
		return regexNode{}, &UnsupportedRegexError{Feature: "casefold_backreference"}
	}
	s := "\\k<" + regexName(id) + ">"
	w := p.captures[id].width
	return regexNode{text: s, min: w.min, max: w.max, repeatable: true}, nil
}

const pythonWhitespace = "\\x09-\\x0d\\x1c-\\x20\\x85\\xa0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000"

func (p *regexParser) category(r rune) string {
	word := "\\p{L}\\p{N}_"
	digits := "\\p{Nd}"
	spaces := pythonWhitespace
	if p.flags.ascii {
		word = "A-Za-z0-9_"
		digits = "0-9"
		spaces = "\\x09-\\x0d "
	}
	switch r {
	case 'w':
		return "[" + word + "]"
	case 'W':
		return "[^" + word + "]"
	case 'd':
		return "[" + digits + "]"
	case 'D':
		return "[^" + digits + "]"
	case 's':
		return "[" + spaces + "]"
	default:
		return "[^" + spaces + "]"
	}
}
func (p *regexParser) escape(inClass bool) (regexNode, error) {
	if p.pos >= len(p.input) {
		return regexNode{}, regexSyntaxError()
	}
	r := p.input[p.pos]
	p.pos++
	if strings.ContainsRune("wWdDsS", r) {
		return regexNode{text: p.category(r), min: 1, max: 1, repeatable: true}, nil
	}
	switch r {
	case 'A':
		if inClass {
			return regexNode{}, regexSyntaxError()
		}
		return regexNode{text: "\\A"}, nil
	case 'Z':
		if inClass {
			return regexNode{}, regexSyntaxError()
		}
		return regexNode{text: "\\z"}, nil
	case 'b', 'B':
		if inClass {
			if r == 'b' {
				return p.literal('\b'), nil
			}
			return regexNode{}, regexSyntaxError()
		}
		w := p.category('w')
		boundary := "(?:(?<=" + w + ")(?!" + w + ")|(?<!" + w + ")(?=" + w + "))"
		if r == 'B' {
			// In the reference Python3.11 dialect \B does not match an empty
			// subject, even though neither side is a word character.
			boundary = "(?!" + boundary + ")(?=[\\s\\S]|(?<=[\\s\\S]))"
		}
		return regexNode{text: boundary}, nil
	case 'a':
		return p.literal('\a'), nil
	case 'f':
		return p.literal('\f'), nil
	case 'n':
		return p.literal('\n'), nil
	case 'r':
		return p.literal('\r'), nil
	case 't':
		return p.literal('\t'), nil
	case 'v':
		return p.literal('\v'), nil
	case 'x', 'u', 'U':
		width := 2
		if r == 'u' {
			width = 4
		} else if r == 'U' {
			width = 8
		}
		if p.pos+width > len(p.input) {
			return regexNode{}, regexSyntaxError()
		}
		text := string(p.input[p.pos : p.pos+width])
		for _, c := range text {
			if !strings.ContainsRune("0123456789abcdefABCDEF", c) {
				return regexNode{}, regexSyntaxError()
			}
		}
		v, e := strconv.ParseUint(text, 16, 32)
		if e != nil || v > utf8.MaxRune || (v >= 0xd800 && v <= 0xdfff) {
			return regexNode{}, regexSyntaxError()
		}
		p.pos += width
		return p.literal(rune(v)), nil
	case 'z':
		return regexNode{}, &UnsupportedRegexError{Feature: "python314_end_anchor"}
	case 'N':
		// Unicode name escapes require the frozen Unicode-name database. They
		// are never interpreted as a literal .NET escape.
		return regexNode{}, &UnsupportedRegexError{Feature: "unicode_name_escape"}
	}
	if r >= '0' && r <= '9' {
		digits := []rune{r}
		if r == '0' || inClass || (p.pos+1 < len(p.input) && r <= '7' && p.input[p.pos] >= '0' && p.input[p.pos] <= '7' && p.input[p.pos+1] >= '0' && p.input[p.pos+1] <= '7') {
			if r > '7' {
				return regexNode{}, regexSyntaxError()
			}
			for len(digits) < 3 && p.pos < len(p.input) && p.input[p.pos] >= '0' && p.input[p.pos] <= '7' {
				digits = append(digits, p.input[p.pos])
				p.pos++
			}
			v, e := strconv.ParseUint(string(digits), 8, 16)
			if e != nil || v > 255 {
				return regexNode{}, regexSyntaxError()
			}
			return p.literal(rune(v)), nil
		}
		if p.pos < len(p.input) && p.input[p.pos] >= '0' && p.input[p.pos] <= '9' {
			digits = append(digits, p.input[p.pos])
			p.pos++
		}
		v, _ := strconv.Atoi(string(digits))
		return p.backref(v)
	}
	if r < 128 && unicode.IsLetter(r) {
		return regexNode{}, regexSyntaxError()
	}
	return p.literal(r), nil
}

type foldPair struct{ from, to rune }

var foldOnce sync.Once
var foldPairs []foldPair

// pythonCaseFoldExtras freezes CPython 3.11's re._casefix equivalences.
// Go's SimpleFold tables differ between supported toolchains; in particular
// older releases omit the Greek dialytika/tonos and long-s/t ligature pairs.
// This supplement is local to regex translation and never changes Go's tables.
var pythonCaseFoldExtras = map[rune][]rune{
	0x49:   {0x69, 0x130, 0x131},
	0x69:   {0x49, 0x130, 0x131},
	0x73:   {0x17f},
	0xb5:   {0x3bc},
	0x130:  {0x49, 0x69, 0x131},
	0x131:  {0x49, 0x69, 0x130},
	0x17f:  {0x73},
	0x345:  {0x3b9, 0x1fbe},
	0x390:  {0x1fd3},
	0x3b0:  {0x1fe3},
	0x3b2:  {0x3d0},
	0x3b5:  {0x3f5},
	0x3b8:  {0x3d1},
	0x3b9:  {0x345, 0x1fbe},
	0x3ba:  {0x3f0},
	0x3bc:  {0xb5},
	0x3c0:  {0x3d6},
	0x3c1:  {0x3f1},
	0x3c2:  {0x3c3},
	0x3c3:  {0x3c2},
	0x3c6:  {0x3d5},
	0x3d0:  {0x3b2},
	0x3d1:  {0x3b8},
	0x3d5:  {0x3c6},
	0x3d6:  {0x3c0},
	0x3f0:  {0x3ba},
	0x3f1:  {0x3c1},
	0x3f5:  {0x3b5},
	0x432:  {0x1c80},
	0x434:  {0x1c81},
	0x43e:  {0x1c82},
	0x441:  {0x1c83},
	0x442:  {0x1c84, 0x1c85},
	0x44a:  {0x1c86},
	0x463:  {0x1c87},
	0x1c80: {0x432},
	0x1c81: {0x434},
	0x1c82: {0x43e},
	0x1c83: {0x441},
	0x1c84: {0x442, 0x1c85},
	0x1c85: {0x442, 0x1c84},
	0x1c86: {0x44a},
	0x1c87: {0x463},
	0x1c88: {0xa64b},
	0x1e61: {0x1e9b},
	0x1e9b: {0x1e61},
	0x1fbe: {0x345, 0x3b9},
	0x1fd3: {0x390},
	0x1fe3: {0x3b0},
	0xa64b: {0x1c88},
	0xfb05: {0xfb06},
	0xfb06: {0xfb05},
}

func unicodeFoldSet(r rune) []rune {
	values := map[rune]bool{}
	pending := []rune{r}
	for len(pending) > 0 {
		current := pending[len(pending)-1]
		pending = pending[:len(pending)-1]
		if values[current] {
			continue
		}
		values[current] = true
		pending = append(pending, unicode.SimpleFold(current))
		pending = append(pending, pythonCaseFoldExtras[current]...)
	}
	out := make([]rune, 0, len(values))
	for value := range values {
		out = append(out, value)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func unicodeCaseLiteral(r rune) string {
	set := unicodeFoldSet(r)
	if len(set) == 1 {
		return regexp2.Escape(string(r))
	}
	return "[" + string(set) + "]"
}
func unicodeCaseRange(lo, hi rune) string {
	foldOnce.Do(func() {
		for r := rune(0); r <= utf8.MaxRune; r++ {
			if unicode.SimpleFold(r) == r && len(pythonCaseFoldExtras[r]) == 0 {
				continue
			}
			for _, n := range unicodeFoldSet(r) {
				if n != r {
					foldPairs = append(foldPairs, foldPair{r, n})
				}
			}
		}
	})
	extra := map[rune]bool{}
	for _, pair := range foldPairs {
		if pair.from >= lo && pair.from <= hi && (pair.to < lo || pair.to > hi) {
			extra[pair.to] = true
		}
	}
	values := make([]rune, 0, len(extra))
	for r := range extra {
		values = append(values, r)
	}
	sort.Slice(values, func(i, j int) bool { return values[i] < values[j] })
	content := classLiteral(lo) + "-" + classLiteral(hi)
	for i := 0; i < len(values); {
		j := i
		for j+1 < len(values) && values[j+1] == values[j]+1 {
			j++
		}
		if j > i+1 {
			content += classLiteral(values[i]) + "-" + classLiteral(values[j])
		} else {
			for k := i; k <= j; k++ {
				content += classLiteral(values[k])
			}
		}
		i = j + 1
	}
	return "[" + content + "]"
}
func classLiteral(r rune) string {
	if strings.ContainsRune("\\]-^[", r) {
		return "\\" + string(r)
	}
	if r < 32 || r == 127 {
		return fmt.Sprintf("\\x%02x", r)
	}
	return string(r)
}

type classPiece struct {
	text    string
	literal bool
	r       rune
}

func (p *regexParser) classPiece() (classPiece, error) {
	if p.pos >= len(p.input) {
		return classPiece{}, regexSyntaxError()
	}
	r := p.input[p.pos]
	p.pos++
	if r != '\\' {
		return classPiece{literal: true, r: r}, nil
	}
	start := p.pos
	n, e := p.escape(true)
	if e != nil {
		return classPiece{}, e
	}
	if start < len(p.input) && strings.ContainsRune("wWdDsS", p.input[start]) {
		return classPiece{text: n.text}, nil
	}
	// The escape is one literal rune. Decode from its original spelling.
	p.pos = start
	r = p.input[p.pos]
	p.pos++
	var v rune
	switch r {
	case 'a':
		v = '\a'
	case 'b':
		v = '\b'
	case 'f':
		v = '\f'
	case 'n':
		v = '\n'
	case 'r':
		v = '\r'
	case 't':
		v = '\t'
	case 'v':
		v = '\v'
	case 'x', 'u', 'U':
		w := 2
		if r == 'u' {
			w = 4
		} else if r == 'U' {
			w = 8
		}
		value, _ := strconv.ParseUint(string(p.input[p.pos:p.pos+w]), 16, 32)
		p.pos += w
		v = rune(value)
	default:
		if r >= '0' && r <= '7' {
			digits := []rune{r}
			for len(digits) < 3 && p.pos < len(p.input) && p.input[p.pos] >= '0' && p.input[p.pos] <= '7' {
				digits = append(digits, p.input[p.pos])
				p.pos++
			}
			value, _ := strconv.ParseUint(string(digits), 8, 16)
			v = rune(value)
		} else {
			v = r
		}
	}
	return classPiece{literal: true, r: v}, nil
}
func (p *regexParser) characterClass() (regexNode, error) {
	negative := false
	if p.pos < len(p.input) && p.input[p.pos] == '^' {
		negative = true
		p.pos++
	}
	first := true
	var alternatives []string
	for p.pos < len(p.input) {
		if p.input[p.pos] == ']' && !first {
			p.pos++
			text := "(?:" + strings.Join(alternatives, "|") + ")"
			if negative {
				text = "(?:(?!" + text + ")[\\s\\S])"
			}
			return regexNode{text: text, min: 1, max: 1, repeatable: true}, nil
		}
		x, e := p.classPiece()
		if e != nil {
			return regexNode{}, e
		}
		first = false
		if p.pos+1 < len(p.input) && p.input[p.pos] == '-' && p.input[p.pos+1] != ']' {
			p.pos++
			y, e := p.classPiece()
			if e != nil {
				return regexNode{}, e
			}
			if !x.literal || !y.literal || x.r > y.r {
				return regexNode{}, regexSyntaxError()
			}
			content := regexp2.Escape(string(x.r)) + "-" + regexp2.Escape(string(y.r))
			if p.flags.ascii && p.flags.ignoreCase {
				for r := 'A'; r <= 'Z'; r++ {
					if r >= x.r && r <= y.r {
						content += string(r - 'A' + 'a')
					}
				}
				for r := 'a'; r <= 'z'; r++ {
					if r >= x.r && r <= y.r {
						content += string(r - 'a' + 'A')
					}
				}
			}
			text := "[" + content + "]"
			if p.flags.ignoreCase && !p.flags.ascii {
				text = unicodeCaseRange(x.r, y.r)
			}
			alternatives = append(alternatives, text)
		} else if x.literal {
			alternatives = append(alternatives, p.literal(x.r).text)
		} else {
			alternatives = append(alternatives, x.text)
		}
	}
	return regexNode{}, regexSyntaxError()
}
