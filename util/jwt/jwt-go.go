package jwt

import (
	"fmt"

	json_web_token "github.com/dgrijalva/jwt-go"
)

// 生成JWT令牌
func GenerateJwtToken(data map[string]string, secretKey string) string {
	jwtToken := json_web_token.New(json_web_token.SigningMethodHS256)
	payload := json_web_token.MapClaims{}
	for key, value := range data {
		payload[key] = value
	}
	jwtToken.Claims = payload
	t, _ := jwtToken.SignedString([]byte(secretKey))
	return t
}

// 解码JWT令牌
func DecodeJwtToken(tokenStr string, secretKey string) (map[string]string, bool) {
	parsedToken, parseErr := json_web_token.Parse(tokenStr, func(token *json_web_token.Token) (interface{}, error) {
		if _, isValidMethod := token.Method.(*json_web_token.SigningMethodHMAC); !isValidMethod {
			return nil, fmt.Errorf("%v", token.Header["alg"])
		}
		return []byte(secretKey), nil
	})

	if parseErr != nil || !parsedToken.Valid {
		return nil, false
	}

	if payload, isMapClaims := parsedToken.Claims.(json_web_token.MapClaims); isMapClaims {
		decodedData := make(map[string]string)
		for key, value := range payload {
			decodedData[key] = fmt.Sprintf("%v", value)
		}
		return decodedData, true
	}

	return nil, false
}
