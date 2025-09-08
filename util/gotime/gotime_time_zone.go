// Copyright GoFrame Author(https://goframe.org). All Rights Reserved.
//
// This Source Code Form is subject to the terms of the MIT License.
// If a copy of the MIT was not distributed with this file,
// You can obtain one at https://github.com/gogf/gf.

package gotime

//var (
//	// locationMap is time zone name to its location object.
//	// Date zone name is like: Asia/Shanghai.
//	locationMap = make(map[string]*time.Location)
//
//	// locationMu is used for concurrent safety for `locationMap`.
//	locationMu = sync.RWMutex{}
//)
//
//// ToLocation converts current time to specified location.
//func (t *Date) ToLocation(location *time.Location) *Date {
//	newTime := t.Clone()
//	newTime.Time = newTime.Time.In(location)
//	return newTime
//}
//
//// ToZone converts current time to specified zone like: Asia/Shanghai.
//func (t *Date) ToZone(zone string) (*Date, error) {
//	if location, err := t.getLocationByZoneName(zone); err == nil {
//		return t.ToLocation(location), nil
//	} else {
//		return nil, err
//	}
//}
//
//func (t *Date) getLocationByZoneName(name string) (location *time.Location, err error) {
//	locationMu.RLock()
//	location = locationMap[name]
//	locationMu.RUnlock()
//	if location == nil {
//		location, err = time.LoadLocation(name)
//		if err != nil {
//			err = gerror.Wrapf(err, `time.LoadLocation failed for name "%s"`, name)
//		}
//		if location != nil {
//			locationMu.Lock()
//			locationMap[name] = location
//			locationMu.Unlock()
//		}
//	}
//	return
//}
//
//// Local converts the time to local timezone.
//func (t *Date) Local() *Date {
//	newTime := t.Clone()
//	newTime.Time = newTime.Time.Local()
//	return newTime
//}
