// +build ignore

/*
 * Parse /lib/keyboard to create latin1.h table for kernel.
 * mklatinkbd -r prints an array of integers rather than a Rune string literal.
 */

package main

var rflag int
var xflag int

const MAXLD = 2 /* latin1.c assumes this is 2 */

var head *C.char = "" + "/*\n" + " * This is automatically generated by %s from /lib/keyboard\n" + " * Edit /lib/keyboard instead.\n" + " */\n"

/*
 * latin1.c assumes that strlen(ld) is at most 2.
 * It also assumes that latintab[i].ld can be a prefix of latintab[j].ld
 * only when j < i.  We ensure this by sorting the output by prefix length.
 * The so array is indexed by the character value.
 */

type Trie struct {
	n    int
	seq  [MAXLD + 1 + 1]C.char
	r    [256]rune
	link [256]*Trie
}

var root *Trie

func mktrie(seq []C.char) *Trie {
	if root == nil {
		root = malloc(sizeof(*root))
		memset(root, 0, sizeof(*root))
	}

	assert(seq[0] != '\x00')

	tp := &root
	for q := (*uint8)(seq); *(q + 1) != '\x00'; q++ {
		tp = &(*tp).link[*q]
		if *tp == nil {
			*tp = malloc(sizeof(**tp))
			assert(*tp != nil)
			memset(*tp, 0, sizeof(**tp))
			strcpy((*tp).seq, seq)
			(*tp).seq[q+1-(*uint8)(seq)] = '\x00'
		}
	}

	assert(*tp != nil)
	return *tp
}

/* add character sequence s meaning rune r */
func insert(s []C.char, r rune) {
	len := strlen(s)
	lastc := uint8(s[len-1])

	t := mktrie(s)
	if t.r[lastc] != 0 {
		fprint(2, "warning: table duplicate: %s is %C and %C\n", s, t.r[lastc], r)
		return
	}
	t.r[lastc] = r
	t.n++
}

func cprintchar(b *Biobuf, c int) {
	/* print a byte c safe for a C string. */
	switch c {
	case '\'',
		'"',
		'\\':
		Bprint(b, "\\%c", c)
	case '\t':
		Bprint(b, "\\t")
	default:
		if isascii(c) != 0 && isprint(c) != 0 {
			Bprint(b, "%c", c)
		} else {
			Bprint(b, "\\x%.2x", c)
		}
	}
}

func cprints(b *Biobuf, p *C.char) {
	for *p != '\x00' {
		cprintchar(b, *p)
		p++
	}
}

func xprint(b *Biobuf, c int) {
}

func printtrie(b *Biobuf, t *Trie) {
	var i int
	for i = 0; i < 256; i++ {
		if t.link[i] != 0 {
			printtrie(b, t.link[i])
		}
	}
	if t.n == 0 {
		return
	}

	if xflag != 0 {
		for i = 0; i < 256; i++ {
			if t.r[i] == 0 {
				continue
			}
			Bprint(b, "<Multi_key>")
			for p := t.seq; *p != 0; p++ {
				Bprint(b, " %k", *p)
			}
			Bprint(b, " %k : \"%C\" U%04X\n", i, t.r[i], t.r[i])
		}
		return
	}

	Bprint(b, "\t\"")
	cprints(b, t.seq)
	Bprint(b, "\", \"")
	for i = 0; i < 256; i++ {
		if t.r[i] != 0 {
			cprintchar(b, i)
		}
	}
	Bprint(b, "\",\t")
	if rflag != 0 {
		Bprint(b, "{")
		for i = 0; i < 256; i++ {
			if t.r[i] != 0 {
				Bprint(b, " 0x%.4ux,", t.r[i])
			}
		}
		Bprint(b, " }")
	} else {
		Bprint(b, "L\"")
		for i = 0; i < 256; i++ {
			if t.r[i] != 0 {
				Bprint(b, "%C", t.r[i])
			}
		}
		Bprint(b, "\"")
	}
	Bprint(b, ",\n")
}

func readfile(fname *C.char) {
	b := Bopen(fname, OREAD)
	if b == 0 {
		fprint(2, "cannot open \"%s\": %r\n", fname)
		exits("open")
	}

	lineno := 0
	for {
		line := Brdline(b, '\n')
		if line == 0 {
			break
		}
		lineno++
		if line[0] == '#' {
			continue
		}

		r := strtol(line, nil, 16)
		p := strchr(line, ' ')
		if r == 0 || (p != line+4 && p != line+5) || p[0] != ' ' || (p == line+4 && p[1] != ' ') {
			fprint(2, "%s:%d: cannot parse line\n", fname, lineno)
			continue
		}

		p = line + 6
		/*	00AE  Or rO       ®	registered trade mark sign	*/
		inseq := 1
		seq := p
		for ; uint8(*p) < Runeself; p++ {
			if *p == '\x00' || isspace(*p) != 0 {
				if inseq != 0 && p-seq >= 2 {
					*p = '\x00'
					inseq = 0
					insert(seq, r)
					*p = ' '
				}
				if *p == '\x00' {
					break
				}
			} else {
				if inseq == 0 {
					seq = p
					inseq = 1
				}
			}
		}
	}
}

func usage() {
	fprint(2, "usage: mklatinkbd [-r] [/lib/keyboard]\n")
	exits("usage")
}

func main(argc int, argv []*C.char) {
	switch ARGBEGIN {
	case 'r': /* print rune values */
		rflag = 1
	case 'x':
		xflag = 1
	default:
		usage()
	}

	if argc > 1 {
		usage()
	}

	fmtinstall('k', kfmt)
	var tmp2 unknown
	if argc == 1 {
		tmp2 = argv[0]
	} else {
		tmp2 = "/dev/stdin"
	}
	readfile(tmp2)
	var bout Biobuf

	Binit(&bout, 1, OWRITE)
	if xflag != 0 {
		Bprint(&bout, "# Generated by mklatinkbd -x; do not edit.\n")
		for i := 0x20; i < 0x10000; i++ {
			Bprint(&bout, "<Multi_key> <X> <%x> <%x> <%x> <%x> : \"%C\" U%04X\n", (i>>12)&0xf, (i>>8)&0xf, (i>>4)&0xf, i&0xf, i, i)
		}
	}
	if root != nil {
		printtrie(&bout, root)
	}
	exits(0)
}

// X11 key names

var xkey = [68]struct {
	c int
	s *C.char
}{
	' ', "space",
	'!', "exclam",
	'"', "quotedbl",
	'#', "numbersign",
	'$', "dollar",
	'%', "percent",
	'&', "ampersand",
	'\'', "apostrophe",
	'(', "parenleft",
	')', "parenright",
	'*', "asterisk",
	'+', "plus",
	',', "comma",
	'-', "minus",
	'.', "period",
	'/', "slash",
	':', "colon",
	';', "semicolon",
	'<', "less",
	'=', "equal",
	'>', "greater",
	'?', "question",
	'@', "at",
	'[', "bracketleft",
	'\\', "backslash",
	',', "bracketright",
	'^', "asciicircum",
	'_', "underscore",
	'`', "grave",
	'{', "braceleft",
	'|', "bar",
	'}', "braceright",
	'~', "asciitilde",
	0, 0,
}

func kfmt(f *Fmt) int {
	c := va_arg(f.args, int)
	for i := 0; xkey[i].s != 0; i++ {
		if xkey[i].c == c {
			return fmtprint(f, "<%s>", xkey[i].s)
		}
	}
	return fmtprint(f, "<%c>", c)
}