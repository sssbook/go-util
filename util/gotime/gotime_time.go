// Copyright GoFrame Author(https://goframe.org). All Rights Reserved.
//
// This Source Code Form is subject to the terms of the MIT License.
// If a copy of the MIT was not distributed with this file,
// You can obtain one at https://github.com/gogf/gf.

package gotime

import (
	"bytes"
	"strconv"
	"time"

	"github.com/gogf/gf/v2/errors/gcode"
	"github.com/gogf/gf/v2/errors/gerror"
)

// DateTime is a wrapper for time.Time for additional features.
type DateTime struct {
	wrapper
}

// iUnixNano is an interface definition commonly for custom time.Time wrapper.
type iUnixNano interface {
	UnixNano() int64
}

// NewDateTime creates and returns a Date object with given parameter.
// The optional parameter can be type of: time.Time/*time.Time, string or integer.
func NewDateTime(param ...interface{}) *DateTime {
	if len(param) > 0 {
		switch r := param[0].(type) {
		case time.Time:
			return NewDateTimeFromTime(r)
		case *time.Time:
			return NewDateTimeFromTime(*r)

		case DateTime:
			return &r

		case *DateTime:
			return r

		case string:
			if len(param) > 1 {
				switch t := param[1].(type) {
				case string:
					return NewDateTimeFromStrFormat(r, t)
				case []byte:
					return NewDateTimeFromStrFormat(r, string(t))
				}
			}
			return NewDateTimeFromStr(r)

		case []byte:
			if len(param) > 1 {
				switch t := param[1].(type) {
				case string:
					return NewDateTimeFromStrFormat(string(r), t)
				case []byte:
					return NewDateTimeFromStrFormat(string(r), string(t))
				}
			}
			return NewDateTimeFromStr(string(r))

		case int:
			return NewDateTimeFromTimeStamp(int64(r))

		case int64:
			return NewDateTimeFromTimeStamp(r)

		default:
			if v, ok := r.(iUnixNano); ok {
				return NewDateTimeFromTimeStamp(v.UnixNano())
			}
		}
	}
	return &DateTime{
		wrapper{time.Time{}},
	}
}

// GetDateTime creates and returns a time object of now.
func GetDateTime() *DateTime {
	return &DateTime{
		wrapper{time.Now()},
	}
}

// NewDateTimeFromTime creates and returns a Date object with given time.Time object.
func NewDateTimeFromTime(t time.Time) *DateTime {
	return &DateTime{
		wrapper{t},
	}
}

// NewDateTimeFromStr creates and returns a Date object with given string.
// Note that it returns nil if there's error occurs.
func NewDateTimeFromStr(str string) *DateTime {
	if t, err := StrToDateTime(str); err == nil {
		return t
	}
	return nil
}

// NewDateTimeFromStrFormat creates and returns a Date object with given string and
// custom format like: Y-m-d H:i:s.
// Note that it returns nil if there's error occurs.
func NewDateTimeFromStrFormat(str string, format string) *DateTime {
	if t, err := StrToDateTimeFormat(str, format); err == nil {
		return t
	}
	return nil
}

// NewDateTimeFromStrLayout creates and returns a Date object with given string and
// stdlib layout like: 2006-01-02 15:04:05.
// Note that it returns nil if there's error occurs.
func NewDateTimeFromStrLayout(str string, layout string) *DateTime {
	if t, err := StrToDateTimeLayout(str, layout); err == nil {
		return t
	}
	return nil
}

// NewDateTimeFromTimeStamp creates and returns a Date object with given timestamp,
// which can be in seconds to nanoseconds.
// Eg: 1600443866 and 1600443866199266000 are both considered as valid timestamp number.
func NewDateTimeFromTimeStamp(timestamp int64) *DateTime {
	if timestamp == 0 {
		return &DateTime{}
	}
	var sec, nano int64
	if timestamp > 1e9 {
		for timestamp < 1e18 {
			timestamp *= 10
		}
		sec = timestamp / 1e9
		nano = timestamp % 1e9
	} else {
		sec = timestamp
	}
	return &DateTime{
		wrapper{time.Unix(sec, nano)},
	}
}

// Timestamp returns the timestamp in seconds.
func (t *DateTime) Timestamp() int64 {
	return t.UnixNano() / 1e9
}

// TimestampMilli returns the timestamp in milliseconds.
func (t *DateTime) TimestampMilli() int64 {
	return t.UnixNano() / 1e6
}

// TimestampMicro returns the timestamp in microseconds.
func (t *DateTime) TimestampMicro() int64 {
	return t.UnixNano() / 1e3
}

// TimestampNano returns the timestamp in nanoseconds.
func (t *DateTime) TimestampNano() int64 {
	return t.UnixNano()
}

// TimestampStr is a convenience method which retrieves and returns
// the timestamp in seconds as string.
func (t *DateTime) TimestampStr() string {
	return strconv.FormatInt(t.Timestamp(), 10)
}

// TimestampMilliStr is a convenience method which retrieves and returns
// the timestamp in milliseconds as string.
func (t *DateTime) TimestampMilliStr() string {
	return strconv.FormatInt(t.TimestampMilli(), 10)
}

// TimestampMicroStr is a convenience method which retrieves and returns
// the timestamp in microseconds as string.
func (t *DateTime) TimestampMicroStr() string {
	return strconv.FormatInt(t.TimestampMicro(), 10)
}

// TimestampNanoStr is a convenience method which retrieves and returns
// the timestamp in nanoseconds as string.
func (t *DateTime) TimestampNanoStr() string {
	return strconv.FormatInt(t.TimestampNano(), 10)
}

// Month returns the month of the year specified by t.
func (t *DateTime) Month() int {
	return int(t.Time.Month())
}

// Second returns the second offset within the minute specified by t,
// in the range [0, 59].
func (t *DateTime) Second() int {
	return t.Time.Second()
}

// Millisecond returns the millisecond offset within the second specified by t,
// in the range [0, 999].
func (t *DateTime) Millisecond() int {
	return t.Time.Nanosecond() / 1e6
}

// Microsecond returns the microsecond offset within the second specified by t,
// in the range [0, 999999].
func (t *DateTime) Microsecond() int {
	return t.Time.Nanosecond() / 1e3
}

// Nanosecond returns the nanosecond offset within the second specified by t,
// in the range [0, 999999999].
func (t *DateTime) Nanosecond() int {
	return t.Time.Nanosecond()
}

// String returns current time object as string.
func (t *DateTime) String() string {
	if t == nil {
		return ""
	}
	if t.IsZero() {
		return ""
	}
	//return t.wrapper.String()
	return t.Format("Y-m-d H:i:s")
}

// IsZero reports whether t represents the zero time instant,
// January 1, year 1, 00:00:00 UTC.
func (t *DateTime) IsZero() bool {
	if t == nil {
		return true
	}
	return t.Time.IsZero()
}

// Clone returns a new Date object which is a clone of current time object.
func (t *DateTime) Clone() *DateTime {
	return NewDateTime(t.Time)
}

// Add adds the duration to current time.
func (t *DateTime) Add(d time.Duration) *DateTime {
	newTime := t.Clone()
	newTime.Time = newTime.Time.Add(d)
	return newTime
}

// AddStr parses the given duration as string and adds it to current time.
func (t *DateTime) AddStr(duration string) (*DateTime, error) {
	if d, err := time.ParseDuration(duration); err != nil {
		err = gerror.Wrapf(err, `time.ParseDuration failed for string "%s"`, duration)
		return nil, err
	} else {
		return t.Add(d), nil
	}
}

// UTC converts current time to UTC timezone.
func (t *DateTime) UTC() *DateTime {
	newTime := t.Clone()
	newTime.Time = newTime.Time.UTC()
	return newTime
}

//// ISO8601 formats the time as ISO8601 and returns it as string.
//func (t *DateTime) ISO8601() string {
//	return t.Layout("2006-01-02T15:04:05-07:00")
//}
//
//// RFC822 formats the time as RFC822 and returns it as string.
//func (t *DateTime) RFC822() string {
//	return t.Layout("Mon, 02 Jan 06 15:04 MST")
//}

// AddDate adds year, month and day to the time.
func (t *DateTime) AddDate(years int, months int, days int) *DateTime {
	newTime := t.Clone()
	newTime.Time = newTime.Time.AddDate(years, months, days)
	return newTime
}

// Round returns the result of rounding t to the nearest multiple of d (since the zero time).
// The rounding behavior for halfway values is to round up.
// If d <= 0, Round returns t stripped of any monotonic clock reading but otherwise unchanged.
//
// Round operates on the time as an absolute duration since the
// zero time; it does not operate on the presentation form of the
// time. Thus, Round(Hour) may return a time with a non-zero
// minute, depending on the time's Location.
func (t *DateTime) Round(d time.Duration) *DateTime {
	newTime := t.Clone()
	newTime.Time = newTime.Time.Round(d)
	return newTime
}

// Truncate returns the result of rounding t down to a multiple of d (since the zero time).
// If d <= 0, Truncate returns t stripped of any monotonic clock reading but otherwise unchanged.
//
// Truncate operates on the time as an absolute duration since the
// zero time; it does not operate on the presentation form of the
// time. Thus, Truncate(Hour) may return a time with a non-zero
// minute, depending on the time's Location.
func (t *DateTime) Truncate(d time.Duration) *DateTime {
	newTime := t.Clone()
	newTime.Time = newTime.Time.Truncate(d)
	return newTime
}

// Equal reports whether t and u represent the same time instant.
// Two times can be equal even if they are in different locations.
// For example, 6:00 +0200 CEST and 4:00 UTC are Equal.
// See the documentation on the Date type for the pitfalls of using == with
// Date values; most code should use Equal instead.
func (t *DateTime) Equal(u *DateTime) bool {
	return t.Time.Equal(u.Time)
}

// Before reports whether the time instant t is before u.
func (t *DateTime) Before(u *DateTime) bool {
	return t.Time.Before(u.Time)
}

// After reports whether the time instant t is after u.
func (t *DateTime) After(u *DateTime) bool {
	return t.Time.After(u.Time)
}

// Sub returns the duration t-u. If the result exceeds the maximum (or minimum)
// value that can be stored in a Duration, the maximum (or minimum) duration
// will be returned.
// To compute t-d for a duration d, use t.Add(-d).
func (t *DateTime) Sub(u *DateTime) time.Duration {
	return t.Time.Sub(u.Time)
}

// StartOfMinute clones and returns a new time of which the seconds is set to 0.
func (t *DateTime) StartOfMinute() *DateTime {
	newTime := t.Clone()
	newTime.Time = newTime.Time.Truncate(time.Minute)
	return newTime
}

// StartOfHour clones and returns a new time of which the hour, minutes and seconds are set to 0.
func (t *DateTime) StartOfHour() *DateTime {
	y, m, d := t.Date()
	newTime := t.Clone()
	newTime.Time = time.Date(y, m, d, newTime.Time.Hour(), 0, 0, 0, newTime.Time.Location())
	return newTime
}

// StartOfDay clones and returns a new time which is the start of day, its time is set to 00:00:00.
func (t *DateTime) StartOfDay() *DateTime {
	y, m, d := t.Date()
	newTime := t.Clone()
	newTime.Time = time.Date(y, m, d, 0, 0, 0, 0, newTime.Time.Location())
	return newTime
}

// StartOfWeek clones and returns a new time which is the first day of week and its time is set to
// 00:00:00.
func (t *DateTime) StartOfWeek() *DateTime {
	weekday := int(t.Weekday())
	return t.StartOfDay().AddDate(0, 0, -weekday)
}

// StartOfMonth clones and returns a new time which is the first day of the month and its is set to
// 00:00:00
func (t *DateTime) StartOfMonth() *DateTime {
	y, m, _ := t.Date()
	newTime := t.Clone()
	newTime.Time = time.Date(y, m, 1, 0, 0, 0, 0, newTime.Time.Location())
	return newTime
}

// StartOfQuarter clones and returns a new time which is the first day of the quarter and its time is set
// to 00:00:00.
func (t *DateTime) StartOfQuarter() *DateTime {
	month := t.StartOfMonth()
	offset := (int(month.Month()) - 1) % 3
	return month.AddDate(0, -offset, 0)
}

// StartOfHalf clones and returns a new time which is the first day of the half year and its time is set
// to 00:00:00.
func (t *DateTime) StartOfHalf() *DateTime {
	month := t.StartOfMonth()
	offset := (int(month.Month()) - 1) % 6
	return month.AddDate(0, -offset, 0)
}

// StartOfYear clones and returns a new time which is the first day of the year and its time is set to
// 00:00:00.
func (t *DateTime) StartOfYear() *DateTime {
	y, _, _ := t.Date()
	newTime := t.Clone()
	newTime.Time = time.Date(y, time.January, 1, 0, 0, 0, 0, newTime.Time.Location())
	return newTime
}

// EndOfMinute clones and returns a new time of which the seconds is set to 59.
func (t *DateTime) EndOfMinute() *DateTime {
	return t.StartOfMinute().Add(time.Minute - time.Nanosecond)
}

// EndOfHour clones and returns a new time of which the minutes and seconds are both set to 59.
func (t *DateTime) EndOfHour() *DateTime {
	return t.StartOfHour().Add(time.Hour - time.Nanosecond)
}

// EndOfDay clones and returns a new time which is the end of day the and its time is set to 23:59:59.
func (t *DateTime) EndOfDay() *DateTime {
	y, m, d := t.Date()
	newTime := t.Clone()
	newTime.Time = time.Date(y, m, d, 23, 59, 59, int(time.Second-time.Nanosecond), newTime.Time.Location())
	return newTime
}

// EndOfWeek clones and returns a new time which is the end of week and its time is set to 23:59:59.
func (t *DateTime) EndOfWeek() *DateTime {
	return t.StartOfWeek().AddDate(0, 0, 7).Add(-time.Nanosecond)
}

// EndOfMonth clones and returns a new time which is the end of the month and its time is set to 23:59:59.
func (t *DateTime) EndOfMonth() *DateTime {
	return t.StartOfMonth().AddDate(0, 1, 0).Add(-time.Nanosecond)
}

// EndOfQuarter clones and returns a new time which is end of the quarter and its time is set to 23:59:59.
func (t *DateTime) EndOfQuarter() *DateTime {
	return t.StartOfQuarter().AddDate(0, 3, 0).Add(-time.Nanosecond)
}

// EndOfHalf clones and returns a new time which is the end of the half year and its time is set to 23:59:59.
func (t *DateTime) EndOfHalf() *DateTime {
	return t.StartOfHalf().AddDate(0, 6, 0).Add(-time.Nanosecond)
}

// EndOfYear clones and returns a new time which is the end of the year and its time is set to 23:59:59.
func (t *DateTime) EndOfYear() *DateTime {
	return t.StartOfYear().AddDate(1, 0, 0).Add(-time.Nanosecond)
}

// MarshalJSON implements the interface MarshalJSON for json.Marshal.
// Note that, DO NOT use `(t *Date) MarshalJSON() ([]byte, error)` as it looses interface
// implement of `MarshalJSON` for struct of Date.
func (t DateTime) MarshalJSON() ([]byte, error) {
	return []byte(`"` + t.String() + `"`), nil
}

// UnmarshalJSON implements the interface UnmarshalJSON for json.Unmarshal.
func (t *DateTime) UnmarshalJSON(b []byte) error {
	if len(b) == 0 {
		t.Time = time.Time{}
		return nil
	}
	newTime, err := StrToDateTime(string(bytes.Trim(b, `"`)))
	if err != nil {
		return err
	}
	t.Time = newTime.Time
	return nil
}

// UnmarshalText implements the encoding.TextUnmarshaler interface.
// Note that it overwrites the same implementer of `time.Time`.
func (t *DateTime) UnmarshalText(data []byte) error {
	vTime := NewDateTime(data)
	if vTime != nil {
		*t = *vTime
		return nil
	}
	return gerror.NewCodef(gcode.CodeInvalidParameter, `invalid time value: %s`, data)
}

// NoValidation marks this struct object will not be validated by package gvalid.
func (t *DateTime) NoValidation() {}

// DeepCopy implements interface for deep copy of current type.
func (t *DateTime) DeepCopy() interface{} {
	return NewDateTime(t.Time)
}
