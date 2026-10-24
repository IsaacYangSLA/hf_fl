package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/IsaacYangSLA/hf_fl/packages/exchange/internal/domain"
)

func (db *DB) Insert(ctx context.Context, table string, values domain.Object) error {
	return db.WithTx(ctx, true, func(tx *Tx) error { return tx.Insert(ctx, table, values) })
}
func (db *DB) Update(ctx context.Context, table string, where, values domain.Object) error {
	return db.WithTx(ctx, true, func(tx *Tx) error { return tx.Update(ctx, table, where, values) })
}

// Insert materializes reference ORM client defaults before writing; generated
// event IDs and defaults are reflected in the supplied values.
func (tx *Tx) Insert(ctx context.Context, table string, values domain.Object) error {
	if err := loadSchema(); err != nil {
		return err
	}
	spec, ok := schemaTables[table]
	if !ok {
		return errors.New("unknown exchange table")
	}
	if values == nil {
		return errors.New("exchange insert values are required")
	}
	known := map[string]columnSpec{}
	for _, c := range spec.Columns {
		known[c.Name] = c
	}
	for name := range values {
		if _, ok := known[name]; !ok {
			return errors.New("unknown exchange column")
		}
	}
	auto := ""
	for _, c := range spec.Columns {
		if c.Auto {
			auto = c.Name
		}
		if value, present := values[c.Name]; present {
			// SQLAlchemy treats None as omitted for scalar INSERT defaults,
			// while JSON's evaluates_none preserves an explicit JSON null.
			if value != nil || c.Kind == "json" || (c.Default == nil && !c.Auto) {
				continue
			}
			if c.Auto {
				delete(values, c.Name)
				continue
			}
		}
		if c.Default != nil {
			switch c.Default.Kind {
			case "now":
				values[c.Name] = float64(time.Now().UnixNano()) / 1e9
			case "map":
				values[c.Name] = domain.Object{}
			case "list":
				values[c.Name] = []any{}
			case "value":
				values[c.Name] = domain.CloneJSON(c.Default.Value)
			default:
				return errors.New("invalid embedded exchange default")
			}
		} else if !c.Nullable && !c.Auto {
			return fmt.Errorf("missing required exchange column %s", c.Name)
		}
	}
	keys := sortedKeys(values)
	names := make([]string, len(keys))
	marks := make([]string, len(keys))
	args := make([]any, len(keys))
	for i, k := range keys {
		value, err := columnValue(known[k], values[k])
		if err != nil {
			return err
		}
		names[i] = quoteID(k)
		marks[i] = "?"
		args[i] = value
		// Reflect the actual SQL type as well as generated defaults.
		if known[k].Kind != "json" {
			values[k] = value
		}
	}
	query := "INSERT INTO " + quoteID(table) + " (" + strings.Join(names, ",") + ") VALUES (" + strings.Join(marks, ",") + ")"
	if auto != "" {
		query += " RETURNING " + quoteID(auto)
		row, err := tx.One(ctx, query, args...)
		if err != nil {
			return err
		}
		if row == nil {
			return errors.New("missing exchange generated identity")
		}
		values[auto] = row[auto]
		return nil
	}
	_, err := tx.Exec(ctx, query, args...)
	return err
}
func (tx *Tx) Update(ctx context.Context, table string, where, values domain.Object) error {
	if err := loadSchema(); err != nil {
		return err
	}
	spec, ok := schemaTables[table]
	if !ok {
		return errors.New("unknown exchange table")
	}
	if len(where) == 0 || len(values) == 0 {
		return errors.New("exchange updates require selection and values")
	}
	known := map[string]columnSpec{}
	for _, c := range spec.Columns {
		known[c.Name] = c
	}
	for name := range values {
		if _, ok := known[name]; !ok {
			return errors.New("unknown exchange column")
		}
	}
	for name := range where {
		if _, ok := known[name]; !ok {
			return errors.New("unknown exchange selection column")
		}
	}
	set, conditions := []string{}, []string{}
	args := []any{}
	for _, k := range sortedKeys(values) {
		value, err := columnValue(known[k], values[k])
		if err != nil {
			return err
		}
		set = append(set, quoteID(k)+"=?")
		args = append(args, value)
	}
	for _, k := range sortedKeys(where) {
		if where[k] == nil {
			conditions = append(conditions, quoteID(k)+" IS NULL")
			continue
		}
		value, err := columnValue(known[k], where[k])
		if err != nil {
			return err
		}
		conditions = append(conditions, quoteID(k)+"=?")
		args = append(args, value)
	}
	_, err := tx.Exec(ctx, "UPDATE "+quoteID(table)+" SET "+strings.Join(set, ",")+" WHERE "+strings.Join(conditions, " AND "), args...)
	return err
}
func sortedKeys(values domain.Object) []string {
	out := make([]string, 0, len(values))
	for k := range values {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
func columnValue(c columnSpec, value any) (any, error) {
	if value == nil {
		if c.Kind == "json" {
			return JSON(nil)
		}
		if !c.Nullable {
			return nil, errors.New("null nonnullable exchange column")
		}
		return nil, nil
	}
	switch c.Kind {
	case "json":
		switch v := value.(type) {
		case json.RawMessage:
			decoded, err := domain.DecodeJSON(v)
			if err != nil {
				return nil, errors.New("invalid exchange JSON column")
			}
			return JSON(decoded)
		default:
			return JSON(value)
		}
	case "bool":
		b, ok := value.(bool)
		if !ok {
			return nil, errors.New("invalid exchange boolean")
		}
		return b, nil
	case "integer":
		n, ok := domain.Int64(value)
		if !ok {
			return nil, errors.New("invalid exchange integer")
		}
		return n, nil
	case "float":
		n, ok := domain.Float(value)
		if !ok {
			return nil, errors.New("invalid exchange number")
		}
		return n, nil
	case "string":
		s, ok := value.(string)
		if !ok {
			return nil, errors.New("invalid exchange string")
		}
		return s, nil
	}
	return nil, errors.New("invalid embedded exchange column kind")
}
