package gotime

import (
	"database/sql/driver"
)

// Scan implements interface used by Scan in package dbstore/sql for Scanning value
// from dbstore to local golang variable.
func (t *Date) Scan(value interface{}) error {
	if t == nil {
		return nil
	}
	newTime := NewDate(value)
	*t = *newTime
	return nil
}

// Value is the interface providing the Value method for package dbstore/sql/driver
// for retrieving value from golang variable to dbstore.
func (t *Date) Value() (driver.Value, error) {
	if t == nil {
		return nil, nil
	}
	if t.IsZero() {
		return nil, nil
	}
	return t.Time, nil
}

// Scan implements interface used by Scan in package dbstore/sql for Scanning value
// from dbstore to local golang variable.
func (t *DateTime) Scan(value interface{}) error {
	if t == nil {
		return nil
	}
	newTime := NewDateTime(value)
	*t = *newTime
	return nil
}

// Value is the interface providing the Value method for package dbstore/sql/driver
// for retrieving value from golang variable to dbstore.
func (t *DateTime) Value() (driver.Value, error) {
	if t == nil {
		return nil, nil
	}
	if t.IsZero() {
		return nil, nil
	}
	return t.Time, nil
}
