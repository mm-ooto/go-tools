/*
	谷歌身份验证器执行步骤：
	1.生成url:GenerateOTP()
	2.校验验证码：CompareCode()
*/

package google_auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"strings"
	"time"
)

// CompareCode 比较验证码是否匹配
// 参数:
//   - shift: 时间偏移量（向前漂移多少个30秒）
//   - code: 要比较的验证码
//   - key: 密钥
//
// 返回:
//   - 验证码是否匹配
func CompareCode(shift int, code uint32, key string) bool {
	now := time.Now().Unix()
	if shift == 0 {
		shift = 1
	}
	for i := 0; i < shift; i++ {
		now -= int64(i) * 30
		if c, _, _ := GenerateCode(key, now); c == code {
			return true
		}
	}
	return false
}

// GenerateOTP 生成 OTP URL
// 参数:
//   - issuer: 发行人
//   - tag: 账户
//
// 返回:
//   - 生成的密钥
//   - Google Authenticator URL
func GenerateOTP(issuer, tag string) (string, string) {
	if issuer == "" {
		issuer = "Issuer"
	}
	secreteKey := GenerateSecretKey()
	return secreteKey, fmt.Sprintf("otpauth://totp/%s?secret=%s&issuer=%s", tag, secreteKey, issuer)
}

// GenerateSecretKey 生成随机密钥
//
// 返回:
//   - 生成的随机密钥
func GenerateSecretKey() string {
	var bytes = make([]byte, 10)
	rand.Read(bytes)
	return base32.StdEncoding.EncodeToString(bytes)
}

// GenerateCode 生成动态验证码
// 参数:
//   - secretKey: 密钥
//   - epochSeconds: 时间戳（秒）
//
// 返回:
//   - 生成的动态验证码
//   - 时间戳（秒）
//   - 错误信息
func GenerateCode(secretKey string, epochSeconds int64) (uint32, int64, error) {
	inputNoSpacesUpper := strings.ToUpper(secretKey)
	key, err := base32.StdEncoding.DecodeString(inputNoSpacesUpper)
	if err != nil {
		return 0, 0, err
	}
	if epochSeconds == 0 {
		epochSeconds = time.Now().Unix()
	}
	pwd := oneTimePassword(key, toBytes(epochSeconds/30))
	return pwd, epochSeconds, nil
}

// toBytes 将整数转换为字节数组
// 参数:
//   - value: 整数值
//
// 返回:
//   - 字节数组
func toBytes(value int64) []byte {
	var result = make([]byte, 8)
	binary.BigEndian.PutUint64(result, uint64(value))
	return result
}

// toUint32 将字节数组转换为 uint32
// 参数:
//   - bytes: 字节数组
//
// 返回:
//   - uint32 值
func toUint32(bytes []byte) uint32 {
	return binary.BigEndian.Uint32(bytes)
}

// oneTimePassword 生成一次性密码（OTP）
// 参数:
//   - key: 密钥
//   - value: 字节数组
//
// 返回:
//   - 生成的一次性密码
func oneTimePassword(key []byte, value []byte) uint32 {
	// sign the value using HMAC-SHA1
	hmacSha1 := hmac.New(sha1.New, key)
	hmacSha1.Write(value)
	hash := hmacSha1.Sum(nil)

	offset := hash[len(hash)-1] & 0x0F
	hashParts := hash[offset : offset+4]
	hashParts[0] = hashParts[0] & 0x7F

	return toUint32(hashParts) % 1000000
}
