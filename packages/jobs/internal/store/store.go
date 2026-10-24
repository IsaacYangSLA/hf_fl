// Package store provides the durable SQL boundary shared by manager services.
package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/IsaacYangSLA/hf_fl/packages/jobs/internal/domain"
	_ "github.com/jackc/pgx/v5/stdlib"
	_ "modernc.org/sqlite"
)

// DB owns a PostgreSQL or isolated SQLite pool. Open does not migrate schemas.
type DB struct {
	SQL     *sql.DB
	Dialect string
}

// Tx is caller-owned; query helpers bind portable SQL markers and timestamps.
type Tx struct {
	SQL     *sql.Tx
	Dialect string
}

func Open(ctx context.Context, databaseURL string) (*DB, error) {
	var driver, dialect, dsn string
	switch {
	case strings.HasPrefix(databaseURL, "postgresql+psycopg://"):
		driver, dialect, dsn = "pgx", "postgresql", "postgresql://"+strings.TrimPrefix(databaseURL, "postgresql+psycopg://")
	case strings.HasPrefix(databaseURL, "postgresql://"), strings.HasPrefix(databaseURL, "postgres://"):
		driver, dialect, dsn = "pgx", "postgresql", databaseURL
	case strings.HasPrefix(databaseURL, "sqlite:") || strings.HasPrefix(databaseURL, "sqlite+pysqlite:"):
		driver, dialect = "sqlite", "sqlite"
		raw := strings.TrimPrefix(databaseURL, "sqlite+pysqlite:")
		raw = strings.TrimPrefix(raw, "sqlite:")
		switch {
		case raw == "//" || raw == "///:memory:" || raw == ":memory:":
			dsn = ":memory:"
		case strings.HasPrefix(raw, "///"):
			dsn = strings.TrimPrefix(raw, "///")
			if dsn == "" || strings.Contains(dsn, "?") || strings.Contains(dsn, "#") {
				return nil, errors.New("invalid SQLite database URL")
			}
		default:
			return nil, errors.New("invalid SQLite database URL")
		}
		options := url.Values{}
		options.Add("_pragma", "foreign_keys(1)")
		options.Add("_pragma", "busy_timeout(30000)")
		// This makes BeginTx acquire the same cross-process reservation as
		// Python BEGIN IMMEDIATE. SQLite remains a single-controller backend.
		options.Set("_txlock", "immediate")
		dsn += "?" + options.Encode()
	default:
		return nil, errors.New("unsupported manager database URL")
	}
	raw, err := sql.Open(driver, dsn)
	if err != nil {
		return nil, errors.New("manager database open failed")
	}
	db := &DB{SQL: raw, Dialect: dialect}
	if dialect == "sqlite" {
		raw.SetMaxOpenConns(1)
		raw.SetMaxIdleConns(1)
	} else {
		raw.SetMaxOpenConns(16)
		raw.SetMaxIdleConns(4)
		raw.SetConnMaxLifetime(30 * time.Minute)
	}
	if err := raw.PingContext(ctx); err != nil {
		raw.Close()
		return nil, errors.New("manager database connection failed")
	}
	return db, nil
}
func (db *DB) Close() error { return db.SQL.Close() }

func (db *DB) WithTx(ctx context.Context, write bool, fn func(*Tx) error) error {
	if db == nil || db.SQL == nil {
		return errors.New("manager database is unconfigured")
	}
	options := &sql.TxOptions{}
	if db.Dialect == "postgresql" {
		options.ReadOnly = !write
	}
	raw, err := db.SQL.BeginTx(ctx, options)
	if err != nil {
		return err
	}
	defer raw.Rollback()
	if err := fn(&Tx{SQL: raw, Dialect: db.Dialect}); err != nil {
		return err
	}
	return raw.Commit()
}
func (db *DB) Rebind(query string) string { return rebind(query, db.Dialect) }
func (tx *Tx) Rebind(query string) string { return rebind(query, tx.Dialect) }
func (db *DB) ForUpdate() string          { return forUpdate(db.Dialect) }
func (tx *Tx) ForUpdate() string          { return forUpdate(tx.Dialect) }
func forUpdate(dialect string) string {
	if dialect == "postgresql" {
		return " FOR UPDATE"
	}
	return ""
}

// rebind replaces unquoted markers while preserving literals and comments.
// Queries are application constants; all caller values remain bound.
func rebind(query, dialect string) string {
	if dialect != "postgresql" {
		return query
	}
	var b strings.Builder
	count := 0
	for i := 0; i < len(query); {
		c := query[i]
		if c == '\'' || c == '"' || c == 96 {
			quote := c
			b.WriteByte(c)
			i++
			for i < len(query) {
				c = query[i]
				b.WriteByte(c)
				i++
				if c == quote {
					if i < len(query) && query[i] == quote {
						b.WriteByte(query[i])
						i++
						continue
					}
					break
				}
			}
		} else if i+1 < len(query) && query[i:i+2] == "--" {
			for i < len(query) && query[i] != '\n' {
				b.WriteByte(query[i])
				i++
			}
		} else if i+1 < len(query) && query[i:i+2] == "/*" {
			b.WriteString("/*")
			i += 2
			depth := 1
			for i < len(query) && depth > 0 {
				if i+1 < len(query) && query[i:i+2] == "/*" {
					depth++
					b.WriteString("/*")
					i += 2
				} else if i+1 < len(query) && query[i:i+2] == "*/" {
					depth--
					b.WriteString("*/")
					i += 2
				} else {
					b.WriteByte(query[i])
					i++
				}
			}
		} else if c == '$' {
			end := i + 1
			for end < len(query) && ((query[end] >= 'a' && query[end] <= 'z') || (query[end] >= 'A' && query[end] <= 'Z') || query[end] == '_' || (end > i+1 && query[end] >= '0' && query[end] <= '9')) {
				end++
			}
			if end < len(query) && query[end] == '$' {
				tag := query[i : end+1]
				after := strings.Index(query[end+1:], tag)
				if after >= 0 {
					after = end + 1 + after + len(tag)
					b.WriteString(query[i:after])
					i = after
					continue
				}
			}
			b.WriteByte(c)
			i++
		} else if c == '?' {
			if i+1 < len(query) && (query[i+1] == '|' || query[i+1] == '&') {
				b.WriteByte(c)
				i++
				continue
			}
			count++
			fmt.Fprintf(&b, "$%d", count)
			i++
		} else {
			b.WriteByte(c)
			i++
		}
	}
	return b.String()
}
func argsFor(dialect string, args []any) ([]any, error) {
	out := make([]any, len(args))
	for i, v := range args {
		switch value := v.(type) {
		case time.Time:
			if dialect == "sqlite" {
				out[i] = value.UTC().Truncate(time.Microsecond).Format("2006-01-02 15:04:05.000000")
			} else {
				out[i] = value.UTC()
			}
		case *time.Time:
			if value == nil {
				out[i] = nil
			} else {
				converted, err := argsFor(dialect, []any{*value})
				if err != nil {
					return nil, err
				}
				out[i] = converted[0]
			}
		case json.RawMessage:
			decoded, err := domain.DecodeJSON(value)
			if err != nil {
				return nil, err
			}
			text, err := JSON(decoded)
			if err != nil {
				return nil, err
			}
			out[i] = text
		case map[string]any, []any, []string, map[string]string:
			text, err := JSON(value)
			if err != nil {
				return nil, err
			}
			out[i] = text
		case json.Number:
			out[i] = value.String()
		default:
			out[i] = v
		}
	}
	return out, nil
}
func (db *DB) Exec(ctx context.Context, query string, args ...any) (sql.Result, error) {
	values, err := argsFor(db.Dialect, args)
	if err != nil {
		return nil, err
	}
	return db.SQL.ExecContext(ctx, db.Rebind(query), values...)
}
func (tx *Tx) Exec(ctx context.Context, query string, args ...any) (sql.Result, error) {
	values, err := argsFor(tx.Dialect, args)
	if err != nil {
		return nil, err
	}
	return tx.SQL.ExecContext(ctx, tx.Rebind(query), values...)
}
func (db *DB) Query(ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	values, err := argsFor(db.Dialect, args)
	if err != nil {
		return nil, err
	}
	return db.SQL.QueryContext(ctx, db.Rebind(query), values...)
}
func (tx *Tx) Query(ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	values, err := argsFor(tx.Dialect, args)
	if err != nil {
		return nil, err
	}
	return tx.SQL.QueryContext(ctx, tx.Rebind(query), values...)
}
func (db *DB) QueryRow(ctx context.Context, query string, args ...any) *sql.Row {
	values, err := argsFor(db.Dialect, args)
	if err != nil {
		return db.SQL.QueryRowContext(ctx, "SELECT hf2l_invalid_sql_argument()")
	}
	return db.SQL.QueryRowContext(ctx, db.Rebind(query), values...)
}
func (tx *Tx) QueryRow(ctx context.Context, query string, args ...any) *sql.Row {
	values, err := argsFor(tx.Dialect, args)
	if err != nil {
		return tx.SQL.QueryRowContext(ctx, "SELECT hf2l_invalid_sql_argument()")
	}
	return tx.SQL.QueryRowContext(ctx, tx.Rebind(query), values...)
}
func (db *DB) One(ctx context.Context, query string, args ...any) (map[string]any, error) {
	rows, err := db.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	if !rows.Next() {
		return nil, rows.Err()
	}
	return scanMap(rows)
}
func (tx *Tx) One(ctx context.Context, query string, args ...any) (map[string]any, error) {
	rows, err := tx.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	if !rows.Next() {
		return nil, rows.Err()
	}
	return scanMap(rows)
}
func (db *DB) All(ctx context.Context, query string, args ...any) ([]map[string]any, error) {
	rows, err := db.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanAll(rows)
}
func (tx *Tx) All(ctx context.Context, query string, args ...any) ([]map[string]any, error) {
	rows, err := tx.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanAll(rows)
}
func scanAll(rows *sql.Rows) ([]map[string]any, error) {
	result := []map[string]any{}
	for rows.Next() {
		row, err := scanMap(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, row)
	}
	return result, rows.Err()
}
func scanMap(rows *sql.Rows) (map[string]any, error) {
	columns, err := rows.Columns()
	if err != nil {
		return nil, err
	}
	values := make([]any, len(columns))
	pointers := make([]any, len(columns))
	for i := range values {
		pointers[i] = &values[i]
	}
	if err := rows.Scan(pointers...); err != nil {
		return nil, err
	}
	if err := loadSchema(); err != nil {
		return nil, err
	}
	result := make(map[string]any, len(columns))
	for i, name := range columns {
		value := values[i]
		if value == nil {
			result[name] = nil
			continue
		}
		if bytes, ok := value.([]byte); ok {
			value = string(bytes)
		}
		switch schemaKinds[name] {
		case "json":
			if text, ok := value.(string); ok {
				value, err = domain.DecodeJSON([]byte(text))
				if err != nil {
					return nil, errors.New("invalid persisted manager JSON")
				}
			}
		case "time":
			parsed, ok := Time(value)
			if !ok {
				return nil, errors.New("invalid persisted manager timestamp")
			}
			value = parsed
		case "bool":
			switch b := value.(type) {
			case bool:
				value = b
			case int64:
				if b != 0 && b != 1 {
					return nil, errors.New("invalid persisted manager boolean")
				}
				value = b == 1
			case string:
				if b != "0" && b != "1" && b != "true" && b != "false" {
					return nil, errors.New("invalid persisted manager boolean")
				}
				value = b == "1" || b == "true"
			default:
				return nil, errors.New("invalid persisted manager boolean")
			}
		}
		result[name] = value
	}
	return result, nil
}

// Time accepts driver timestamps and the prior SQLAlchemy SQLite format.
// Timezone-less legacy SQLite timestamps mean UTC.
func Time(value any) (time.Time, bool) {
	switch v := value.(type) {
	case time.Time:
		return v.UTC(), true
	case *time.Time:
		if v != nil {
			return v.UTC(), true
		}
		return time.Time{}, false
	case string:
		for _, layout := range []string{time.RFC3339Nano, "2006-01-02 15:04:05.999999999Z07:00", "2006-01-02 15:04:05.999999999", "2006-01-02 15:04:05.999999999 -0700 MST", "2006-01-02 15:04:05Z07:00"} {
			if t, err := time.Parse(layout, v); err == nil {
				return t.UTC(), true
			}
		}
	case []byte:
		return Time(string(v))
	}
	return time.Time{}, false
}
func UTC(value time.Time) string { return value.UTC().Format(time.RFC3339Nano) }
func JSON(value any) (string, error) {
	data, err := domain.CanonicalJSON(value)
	return string(data), err
}
