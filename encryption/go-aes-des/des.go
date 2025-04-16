package goaesdes

// DesECBPkcs7Encrypt ECB 加密模式
//
//	data要加密的数据，key要加密的密钥
func DesECBPkcs7Encrypt(data, key []byte) ([]byte, error) {
	return Encrypt(Des, data, key, []byte{}, ECB, Pkcs7)
}

// DesECBPkcs7Decrypt ECB 模式解密
//
//	src密文，key加密时的密钥
func DesECBPkcs7Decrypt(src, key []byte) ([]byte, error) {
	return Decrypt(Des, src, key, []byte{}, ECB, Pkcs7)
}

// DesCBCPkcs7Encrypt CBC 加密模式
//
//	data要加密的数据，key要加密的密钥
func DesCBCPkcs7Encrypt(data, key, iv []byte) ([]byte, error) {
	return Encrypt(Des, data, key, iv, CBC, Pkcs7)
}

// DescCBCPkcs7Decrypt CBC 模式解密
//
//	src密文，key加密时的密钥
func DescCBCPkcs7Decrypt(src, key, iv []byte) ([]byte, error) {
	return Decrypt(Des, src, key, iv, CBC, Pkcs7)
}

// DesCFBPkcs7Encrypt CFB 加密模式
//
//	data要加密的数据，key要加密的密钥
func DesCFBPkcs7Encrypt(data, key, iv []byte) ([]byte, error) {
	return Encrypt(Des, data, key, iv, CFB, Pkcs7)
}

// DesCFBPkcs7Decrypt CFB 模式解密
//
//	src密文，key加密时的密钥
func DesCFBPkcs7Decrypt(src, key, iv []byte) ([]byte, error) {
	return Decrypt(Des, src, key, iv, CFB, Pkcs7)
}

// DesOFBPkcs7Encrypt OFB 加密模式
//
//	data要加密的数据，key要加密的密钥
func DesOFBPkcs7Encrypt(data, key, iv []byte) ([]byte, error) {
	return Encrypt(Des, data, key, iv, OFB, Pkcs7)
}

// DesOFBPkcs7Decrypt OFB 模式解密
//
//	src密文，key加密时的密钥
func DesOFBPkcs7Decrypt(src, key, iv []byte) ([]byte, error) {
	return Decrypt(Des, src, key, iv, OFB, Pkcs7)
}

// DesCTRPkcs7Encrypt CTR 加密模式
//
//	data要加密的数据，key要加密的密钥
func DesCTRPkcs7Encrypt(data, key, iv []byte) ([]byte, error) {
	return Encrypt(Des, data, key, iv, CTR, Pkcs7)
}

// DesCTRPkcs7Decrypt CTR 模式解密
//
//	src密文，key加密时的密钥
func DesCTRPkcs7Decrypt(src, key, iv []byte) ([]byte, error) {
	return Decrypt(Des, src, key, iv, CTR, Pkcs7)
}
