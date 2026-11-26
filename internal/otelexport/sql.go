package otelexport

import "strings"

// sanitizeSQL replaces string and numeric literals with ?, so values such as
// e-mail addresses or password hashes in a query do not end up in the trace.
// Identifiers, including backquoted ones and names containing digits such as
// utf8mb4, are left alone. It does not need to parse SQL: anything it does not
// recognise is copied through.
func sanitizeSQL(sql string) string {
	var b strings.Builder
	b.Grow(len(sql))

	for i := 0; i < len(sql); {
		c := sql[i]
		switch {
		case c == '`':
			j := quotedEnd(sql, i, '`', false)
			b.WriteString(sql[i:j])
			i = j

		case c == '\'' || c == '"':
			i = quotedEnd(sql, i, c, true)
			b.WriteByte('?')

		case isDigit(c) && (i == 0 || !isIdentByte(sql[i-1])):
			i = numberEnd(sql, i)
			b.WriteByte('?')

		case isIdentByte(c):
			j := i
			for j < len(sql) && isIdentByte(sql[j]) {
				j++
			}
			b.WriteString(sql[i:j])
			i = j

		default:
			b.WriteByte(c)
			i++
		}
	}

	return b.String()
}

// quotedEnd returns the index just past the literal starting with the quote at
// sql[start]. A doubled quote stands for the quote itself, and with escapes a
// backslash escapes the next byte. An unterminated literal (the query was cut
// short) runs to the end.
func quotedEnd(sql string, start int, quote byte, escapes bool) int {
	for i := start + 1; i < len(sql); i++ {
		switch sql[i] {
		case '\\':
			if escapes {
				i++
			}
		case quote:
			if i+1 < len(sql) && sql[i+1] == quote {
				i++
				continue
			}
			return i + 1
		}
	}

	return len(sql)
}

// numberEnd returns the index just past the numeric literal at sql[start]:
// decimal, with an optional fraction and exponent, or 0x / 0b prefixed.
func numberEnd(sql string, start int) int {
	i := start
	if sql[i] == '0' && i+1 < len(sql) && (sql[i+1] == 'x' || sql[i+1] == 'X' || sql[i+1] == 'b' || sql[i+1] == 'B') {
		i += 2
		for i < len(sql) && isHexDigit(sql[i]) {
			i++
		}
		return i
	}
	for i < len(sql) && (isDigit(sql[i]) || sql[i] == '.') {
		i++
	}
	if i < len(sql) && (sql[i] == 'e' || sql[i] == 'E') {
		j := i + 1
		if j < len(sql) && (sql[j] == '+' || sql[j] == '-') {
			j++
		}
		if j < len(sql) && isDigit(sql[j]) {
			i = j
			for i < len(sql) && isDigit(sql[i]) {
				i++
			}
		}
	}

	return i
}

// operationName returns the SQL verb, upper-cased, such as SELECT, or "" when
// the text does not start with a word.
func operationName(sql string) string {
	sql = strings.TrimLeft(sql, " \t\r\n(")
	end := 0
	for end < len(sql) && isLetter(sql[end]) {
		end++
	}
	if end == 0 {
		return ""
	}

	return strings.ToUpper(sql[:end])
}

func isDigit(c byte) bool  { return c >= '0' && c <= '9' }
func isLetter(c byte) bool { return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' }

func isHexDigit(c byte) bool {
	return isDigit(c) || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

// isIdentByte reports whether c can be part of an unquoted identifier. Bytes
// of multi-byte UTF-8 characters count, as MySQL allows them in identifiers.
func isIdentByte(c byte) bool {
	return isLetter(c) || isDigit(c) || c == '_' || c == '$' || c >= 0x80
}
