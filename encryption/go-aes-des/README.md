# go-aes-des


## 简介
对称加密

#### 对称加密
 * aes
 * des
 * 3des
  

## 用法

### 对称加密
通用方法
```go
EasyEncrypt(easyType, plaintext, key, iv)
EasyDecrypt(easyType, ciphertext, key, iv)
```
参数 easyType 应该为以下格式:cryptoType/mode/padding 或 cryptoType/mode/padding/transcode

For example:
```go
EasyEncrypt("des/CFB/Pkcs7/Base64", plaintext, key, iv)
EasyDecrypt("des/CFB/Pkcs7/Base64", ciphertext, key, iv)

EasyEncrypt("aes/CTR/Pkcs7/Hex", plaintext, key, iv)
EasyDecrypt("aes/CTR/Pkcs7/Hex", ciphertext, key, iv)

EasyEncrypt("3des/ECB/Pkcs5/Hex", plaintext, key, iv)
EasyDecrypt("3des/ECB/Pkcs5/Hex", ciphertext, key, iv)
```
核心方法是 Encrypt() 和 Decrypt(). 其他方法都是基于这两个方法的门面.
#### 关于补码
* noPadding: 要求原始数据长度必须是当前算法的block的正整数倍。
* zeorPadding: 会用0填充，当原始数据也是以0结尾时，会有问题。
* pkcs5Padding: 补码长度固定为8，在某些算法中，和block不匹配，会有异常
* pkcs7Padding: Pkcs5Padding的超集，补码的位置是动态的，适用各种算法，推荐。
