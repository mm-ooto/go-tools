package google_auth

import (
	"fmt"
	"github.com/go-errors/errors"
	"strconv"
	"time"

	redisC "github.com/go-redis/redis"
)

// RoleCodeType 定义 RoleCodeType 类型
type RoleCodeType string

var (
	// GoogleTimeShift Google 时间偏移量
	GoogleTimeShift int
	// GoogleIssuer Google 发行人
	GoogleIssuer string
	// customRoleCodeTypes 存储自定义的 RoleCodeType 值
	customRoleCodeTypes = make(map[string]RoleCodeType)
)

// SetCustomRoleCodeType 设置自定义的 RoleCodeType 值
// 参数:
//   - key: 自定义 RoleCodeType 的键
//   - value: 自定义 RoleCodeType 的值
func SetCustomRoleCodeType(key string, value RoleCodeType) {
	customRoleCodeTypes[key] = value
}

// UserGoogleSecreteKey 生成用户谷歌密钥Key
// 参数:
//   - userID: 用户ID
//   - userType: 用户类型
//   - secreteKey: 密钥
//
// 返回:
//   - 生成的用户谷歌密钥Key
func UserGoogleSecreteKey(userID uint, userType RoleCodeType, secreteKey string) string {
	// 检查是否是自定义的 RoleCodeType
	if customType, ok := customRoleCodeTypes[string(userType)]; ok {
		userType = customType
	}
	return fmt.Sprintf("google_auth-user_id-%d-%s-secrete_key-%s", userID, userType, secreteKey)
}

// SetGoogleCodeToRedis 将用户谷歌验证码保存到redis
// 参数:
//   - redis: Redis 客户端
//   - userID: 用户ID
//   - userType: 用户类型
//   - secreteKey: 密钥
//   - code: 验证码
//   - expiration: 过期时间
func SetGoogleCodeToRedis(redis *redisC.Client, userID uint, userType RoleCodeType, secreteKey, code string, expiration time.Duration) {
	userSecreteKey := UserGoogleSecreteKey(userID, userType, secreteKey)
	redis.Set(userSecreteKey, code, expiration)
}

// CheckUserGoogleCodeExists 检查用户谷歌验证码是否存在
// 参数:
//   - redis: Redis 客户端
//   - userID: 用户ID
//   - userType: 用户类型
//   - code: 验证码
//   - secreteKey: 密钥
//
// 返回:
//   - 验证码是否存在
//   - 错误信息
func CheckUserGoogleCodeExists(redis *redisC.Client, userID uint, userType RoleCodeType, code, secreteKey string) (bool, error) {
	userSecreteKey := UserGoogleSecreteKey(userID, userType, secreteKey)
	getCmd := redis.Get(userSecreteKey)
	err := getCmd.Err()
	if err != nil && errors.Is(err, redisC.Nil) {
		err = nil
	}
	return getCmd.Val() == code, err
}

// ConfigGoogleTimeShift 从数据配置中获取shift,issuer
// 参数:
//   - googleTimeShiftLimit: 时间偏移量限制
//   - googleAuthenticatorIssuer: 发行人
func ConfigGoogleTimeShift(googleTimeShiftLimit, googleAuthenticatorIssuer string) {
	shift, err := strconv.ParseInt(googleTimeShiftLimit, 10, 64)
	if err != nil {
		fmt.Printf("getGoogleTimeShiftLimit error:%s\n", err.Error())
	}
	GoogleTimeShift = int(shift)
	GoogleIssuer = googleAuthenticatorIssuer
}

// GenerateGoogleAuthSecreteKey 生成谷歌验证密钥Key
// 参数:
//   - userID: 用户ID
//   - userType: 用户类型
//
// 返回:
//   - 生成的谷歌验证密钥Key
func GenerateGoogleAuthSecreteKey(userID uint, userType RoleCodeType) string {
	// 检查是否是自定义的 RoleCodeType
	if customType, ok := customRoleCodeTypes[string(userType)]; ok {
		userType = customType
	}
	return fmt.Sprintf("google_auth-user_id-%d-%s-update_google_auth_operation", userID, userType)
}

// SetGoogleAuthSecreteKeyToRedis 将生成的谷歌验证密钥暂存到redis中便于后续修改使用
// 参数:
//   - redis: Redis 客户端
//   - userID: 用户ID
//   - userType: 用户类型
//   - secreteKey: 密钥
//   - expiration: 过期时间
func SetGoogleAuthSecreteKeyToRedis(redis *redisC.Client, userID uint, userType RoleCodeType, secreteKey string, expiration time.Duration) {
	userSecreteKey := GenerateGoogleAuthSecreteKey(userID, userType)
	redis.Set(userSecreteKey, secreteKey, expiration)
}

// GetGoogleAuthSecreteKey 获取谷歌验证密钥
// 参数:
//   - redis: Redis 客户端
//   - userID: 用户ID
//   - userType: 用户类型
//
// 返回:
//   - 谷歌验证密钥
//   - 错误信息
func GetGoogleAuthSecreteKey(redis *redisC.Client, userID uint, userType RoleCodeType) (string, error) {
	userSecreteKey := GenerateGoogleAuthSecreteKey(userID, userType)
	getCmd := redis.Get(userSecreteKey)
	err := getCmd.Err()
	if err != nil && errors.Is(err, redisC.Nil) {
		err = nil
	}
	return getCmd.Val(), err
}

// RemoveGoogleAuthSecreteKey 删除暂存谷歌的密钥
// 参数:
//   - redis: Redis 客户端
//   - userID: 用户ID
//   - userType: 用户类型
func RemoveGoogleAuthSecreteKey(redis *redisC.Client, userID uint, userType RoleCodeType) {
	userSecreteKey := GenerateGoogleAuthSecreteKey(userID, userType)
	redis.Del(userSecreteKey)
}

// GetOrGenerateGoogleAuthSecreteKey 获取谷歌密钥不存在的话生成新的并保存(有效期为24h)
// 参数:
//   - redis: Redis 客户端
//   - userID: 用户ID
//   - userType: 用户类型
//   - account: 账户
//
// 返回:
//   - 谷歌验证密钥
//   - 错误信息
func GetOrGenerateGoogleAuthSecreteKey(redis *redisC.Client, userID uint, userType RoleCodeType, account string) (string, error) {
	key, err := GetGoogleAuthSecreteKey(redis, userID, userType)
	if err != nil {
		return "", err
	}
	if len(key) == 0 {
		secreteKey, pauth := GenerateOTP(GoogleIssuer, account)
		SetGoogleAuthSecreteKeyToRedis(redis, userID, userType, secreteKey, 24*time.Hour)
		return pauth, nil
	}
	pauth := GoogleAuthURL(account, key, GoogleIssuer)
	return pauth, nil
}

// GoogleAuthURL 生成 Google Authenticator URL
// 参数:
//   - account: 账户
//   - secreteKey: 密钥
//   - issuer: 发行人
//
// 返回:
//   - Google Authenticator URL
func GoogleAuthURL(account, secreteKey, issuer string) string {
	return fmt.Sprintf("otpauth://totp/%s?secret=%s&issuer=%s", account, secreteKey, issuer)
}
