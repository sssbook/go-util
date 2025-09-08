package utils

import (
	"crypto/md5"
	"crypto/rand"
	"errors"
	"fmt"
	gouuid "github.com/nu7hatch/gouuid"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// 消除重复元素
func ArrayUniqueSet(sliceArray []string) []string {
	uniqueSet := make(map[string]struct{}, len(sliceArray))
	index := 0
	for _, item := range sliceArray {
		if _, found := uniqueSet[item]; !found {
			uniqueSet[item] = struct{}{}
			sliceArray[index] = item
			index++
		}
	}
	return sliceArray[:index]
}

func GetAgeWithIdentificationNumber(identificationNumber string) (string, error) {
	reg := regexp.MustCompile(`^[1-9]\d{5}(18|19|20)(\d{2})((0[1-9])|(1[0-2]))(([0-2][1-9])|10|20|30|31)\d{3}[0-9Xx]$`)
	params := reg.FindStringSubmatch(identificationNumber)
	if len(params) == 0 {
		return "", errors.New("身份证有误")
	}
	birYear, _ := strconv.Atoi(params[1] + params[2])
	birMonth, _ := strconv.Atoi(params[3])
	age := time.Now().Year() - birYear
	if int(time.Now().Month()) < birMonth {
		age--
	}
	return fmt.Sprintf("%d", age), nil
}

func GetSexWithIdentificationNumber(identificationNumber string) (string, error) {
	if len(identificationNumber) != 18 {
		return "", errors.New("身份证有误")
	}
	sexStr := identificationNumber[16:17]
	sexCode, err := strconv.Atoi(sexStr)
	if err != nil {
		return "", errors.New("身份证有误")
	}
	if sexCode%2 == 0 {
		return "女", nil
	} else {
		return "男", nil
	}
}
func Difference(a, b []string) []string {
	m := make(map[string]bool)
	for _, item := range b {
		m[item] = true
	}

	var diff []string
	for _, item := range a {
		if !m[item] {
			diff = append(diff, item)
		}
	}

	return diff
}

// 数组转，号分割字符串
func ArrayConvertToString(array interface{}) string {
	return strings.Replace(strings.Trim(fmt.Sprint(array), "[]"), " ", ",", -1)
}

// 随机生成32的密钥
func SignKey() string {
	var b = make([]byte, 20)
	rand.Read(b)
	mb := md5.Sum(b)
	return fmt.Sprintf("%x", mb[:])
}

// todo
func SerialNumber() string {
	c, err := gouuid.NewV4()
	if err != nil {
		return ""
	}
	return fmt.Sprintf("%x", c[:])
}

const alpha = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz_-"

// Nonce 生成指定长度位的随机数
func Nonce(n int) string {
	var bytes = make([]byte, n)
	rand.Read(bytes)
	for i, b := range bytes {
		bytes[i] = alpha[b&63]
	}
	return string(bytes)
}
