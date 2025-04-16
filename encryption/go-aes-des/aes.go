package goaesdes

// The key argument should be the AES key,
// either 16, 24, or 32 bytes to select
// AES-128, AES-192, or AES-256.

// AesECBPkcs7Encrypt ECB 加密模式
//
//	data要加密的数据，key要加密的密钥
func AesECBPkcs7Encrypt(data, key []byte) ([]byte, error) {
	return Encrypt(Aes, data, key, []byte{}, ECB, Pkcs7)
}

// AesECBPkcs7Decrypt ECB 模式解密
//
//	src密文，key加密时的密钥
func AesECBPkcs7Decrypt(src, key []byte) ([]byte, error) {
	return Decrypt(Aes, src, key, []byte{}, ECB, Pkcs7)
}

// AesCBCPkcs7Encrypt CBC 加密模式
//
//	data要加密的数据，key要加密的密钥
func AesCBCPkcs7Encrypt(data, key, iv []byte) ([]byte, error) {
	return Encrypt(Aes, data, key, iv, CBC, Pkcs7)
}

// AesCBCPkcs7Decrypt CBC 模式解密
//
//	src密文，key加密时的密钥
func AesCBCPkcs7Decrypt(src, key, iv []byte) ([]byte, error) {
	return Decrypt(Aes, src, key, iv, CBC, Pkcs7)
}

// AesCFBPkcs7Encrypt CFB 加密模式
//
//	data要加密的数据，key要加密的密钥
func AesCFBPkcs7Encrypt(data, key, iv []byte) ([]byte, error) {
	return Encrypt(Aes, data, key, iv, CFB, Pkcs7)
}

// AesCFBPkcs7Decrypt CFB 模式解密
//
//	src密文，key加密时的密钥
func AesCFBPkcs7Decrypt(src, key, iv []byte) ([]byte, error) {
	return Decrypt(Aes, src, key, iv, CFB, Pkcs7)
}

// AesOFBPkcs7Encrypt OFB 加密模式
//
//	data要加密的数据，key要加密的密钥
func AesOFBPkcs7Encrypt(data, key, iv []byte) ([]byte, error) {
	return Encrypt(Aes, data, key, iv, OFB, Pkcs7)
}

// AesOFBPkcs7Decrypt OFB 模式解密
//
//	src密文，key加密时的密钥
func AesOFBPkcs7Decrypt(src, key, iv []byte) ([]byte, error) {
	return Decrypt(Aes, src, key, iv, OFB, Pkcs7)
}

// AesCTRPkcs7Encrypt CTR 加密模式
//
//	data要加密的数据，key要加密的密钥
func AesCTRPkcs7Encrypt(data, key, iv []byte) ([]byte, error) {
	return Encrypt(Aes, data, key, iv, CTR, Pkcs7)
}

// AesCTRPkcs7Decrypt CTR 模式解密
//
//	src密文，key加密时的密钥
func AesCTRPkcs7Decrypt(src, key, iv []byte) ([]byte, error) {
	return Decrypt(Aes, src, key, iv, CTR, Pkcs7)
}
