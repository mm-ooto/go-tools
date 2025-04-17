# Google Authenticator 功能说明

## 概述

本文件夹包含与 Google Authenticator 相关的功能，包括生成和验证 Google 验证码、管理密钥等操作。这些功能主要用于实现双因素认证（2FA）。具体文件包括 `google_auth.go` 和 `otpauth.go`。

## 文件说明

### google_auth.go

#### 概述

`google_auth.go` 文件提供了与 Google Authenticator 相关的功能，包括生成和验证 Google 验证码、管理密钥等操作。这些功能主要用于实现双因素认证（2FA）。

#### 主要功能

1. **生成用户谷歌密钥**
2. **将用户谷歌验证码保存到 Redis**
3. **检查用户谷歌验证码是否存在**
4. **配置 Google 时间偏移量和发行人**
5. **生成谷歌验证密钥**
6. **将生成的谷歌验证密钥暂存到 Redis**
7. **获取谷歌验证密钥**
8. **删除暂存的谷歌密钥**
9. **获取或生成谷歌密钥**
10. **生成 Google Authenticator URL**

#### 使用方法

##### 1. 生成用户谷歌密钥

```go
    userSecreteKey := UserGoogelSecreteKey(userID, userType, secreteKey)
```

##### 2. 将用户谷歌验证码保存到 Redis
```go
    SetGoogelCodeToRedis(redis, userID, userType, secreteKey, code, expiration)
```

##### 3. 检查用户谷歌验证码是否存在
```go
    exists, err := CheckUserGoogleCodeExists(redis, userID, userType, code, secreteKey)
    if err != nil {
        // 处理错误
    }
    if exists {
        // 验证码存在
    }
```

##### 4. 配置 Google 时间偏移量和发行人
```go
    ConfigGoogleTimeShift(googleTimeShiftLimit, googleAuthenticatorIssuer)
```

##### 5. 生成谷歌验证密钥
```go
    userSecreteKey := GenerateGoogleAuthSecreteKey(userID, userType)
```

##### 6. 将生成的谷歌验证密钥暂存到 Redis
```go
    SetGoogleAuthSecreteKeyToRedis(redis, userID, userType, secreteKey, expiration)
```

##### 7. 获取谷歌验证密钥
```go
    key, err := GetGoogleAuthSecreteKey(redis, userID, userType)
    if err != nil {
        // 处理错误
    }
```

##### 8. 删除暂存的谷歌密钥
```go
    RemoveGoogleAuthSecreteKey(redis, userID, userType)
```

##### 9. 获取或生成谷歌密钥
```go
    pauth, err := GetOrGenerateGoogleAuthSecreteKey(redis, userID, userType, account)
    if err != nil {
        // 处理错误
    }
```

##### 10. 生成 Google Authenticator URL
```go
    url := googleAuthURL(account, secreteKey, issuer)
```

#### 自定义 RoleCodeType

##### 为了允许调用者使用自定义的 RoleCodeType 值，可以使用 SetCustomRoleCodeType 函数。

##### 示例：
```go
   // 设置自定义的 RoleCodeType 值
    SetCustomRoleCodeType("custom_role", "custom_value")

    // 使用自定义的 RoleCodeType 值
    userType := RoleCodeType("custom_role")
    secreteKey := "your_secret_key"
    code := "123456"
    expiration := 10 * time.Minute

    SetGoogelCodeToRedis(redis, userID, userType, secreteKey, code, expiration)
    exists, err := CheckUserGoogleCodeExists(redis, userID, userType, code, secreteKey)
    if err != nil {
        // 处理错误
    }
    if exists {
        // 验证码存在
    }
```


### otpauth.go

#### 概述

`otpauth.go` 文件提供了生成和验证 Google Authenticator 代码的功能，主要用于实现双因素认证（2FA）。这些功能包括生成密钥、生成 OTP URL、生成动态验证码等。

#### 主要功能

1. **比较验证码是否匹配**
2. **生成 OTP URL**
3. **生成随机密钥**
4. **生成动态验证码**
5. **生成一次性密码（OTP）**

#### 使用方法

##### 1. 比较验证码是否匹配

```go
   isMatch := CompareCode(shift, code, key)
```

##### 2. 生成 OTP URL
```go
   secreteKey, url := GenerateOTP(issuer, tag)
```

##### 3. 生成随机密钥
```go
   secreteKey := GenerateSecretKey()
```

##### 4. 生成动态验证码
```go
    code, epochSeconds, err := GenerateCode(secretKey, epochSeconds)
    if err != nil {
        // 处理错误
    }
```

##### 5. 生成一次性密码（OTP）
```go
    otp := oneTimePassword(key, value)
```
