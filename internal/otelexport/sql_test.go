package otelexport

import "testing"

func TestSanitizeSQL(t *testing.T) {
	cases := []struct{ in, want string }{
		{"SELECT 1", "SELECT ?"},
		{"SELECT option_value FROM wp_options WHERE option_name = 'siteurl' LIMIT 1",
			"SELECT option_value FROM wp_options WHERE option_name = ? LIMIT ?"},
		{`UPDATE users SET pass = "x\"y", n = -1.5e3 WHERE id IN (1, 2,3)`,
			`UPDATE users SET pass = ?, n = -? WHERE id IN (?, ?,?)`},
		{"SELECT 'it''s', 'a\\'b' FROM t", "SELECT ?, ? FROM t"},
		{"SET NAMES utf8mb4 COLLATE utf8mb4_unicode_520_ci", "SET NAMES utf8mb4 COLLATE utf8mb4_unicode_520_ci"},
		{"SELECT * FROM `table 1` WHERE `col2` = 0x1F", "SELECT * FROM `table 1` WHERE `col2` = ?"},
		{"select * from `todos` where id = ? and t2.c3 > 10", "select * from `todos` where id = ? and t2.c3 > ?"},
		{"SELECT * FROM 日本1 WHERE x = 'v'", "SELECT * FROM 日本1 WHERE x = ?"},
		// Cut short by the kernel in the middle of a literal.
		{"INSERT INTO t VALUES ('secret", "INSERT INTO t VALUES (?"},
	}
	for _, tc := range cases {
		if got := sanitizeSQL(tc.in); got != tc.want {
			t.Errorf("sanitizeSQL(%q)\n got %q\nwant %q", tc.in, got, tc.want)
		}
	}
}

func TestOperationName(t *testing.T) {
	cases := map[string]string{
		"SELECT 1":                    "SELECT",
		"  select * from t":           "SELECT",
		"(SELECT 1) UNION (SELECT 2)": "SELECT",
		"SHOW TABLES LIKE 'wp_x'":     "SHOW",
		"set session sql_mode='x'":    "SET",
		"":                            "",
		"/* comment */ SELECT 1":      "",
	}
	for in, want := range cases {
		if got := operationName(in); got != want {
			t.Errorf("operationName(%q) = %q, want %q", in, got, want)
		}
	}
}
