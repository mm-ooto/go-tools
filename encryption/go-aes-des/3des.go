package goaesdes

// TripleDesECBPkcs7Encrypt ECB 加密模式
//
//	data要加密的数据，key要加密的密钥
func TripleDesECBPkcs7Encrypt(data, key []byte) ([]byte, error) {
	return Encrypt(TriDes, data, key, []byte{}, ECB, Pkcs7)
}

// TripleDesECBPkcs7Decrypt ECB 模式解密
//
//	src密文，key加密时的密钥
func TripleDesECBPkcs7Decrypt(src, key []byte) ([]byte, error) {
	return Decrypt(TriDes, src, key, []byte{}, ECB, Pkcs7)
}

// TripleDesECBPkcs5Encrypt ECB 加密模式
//
//	data要加密的数据，key要加密的密钥 PK5
func TripleDesECBPkcs5Encrypt(data, key []byte) ([]byte, error) {
	return Encrypt(TriDes, data, key, []byte{}, ECB, Pkcs5)
}

// TripleDesECBPkcs5Decrypt ECB 模式解密
//
//	src密文，key加密时的密钥
func TripleDesECBPkcs5Decrypt(src, key []byte) ([]byte, error) {
	return Decrypt(TriDes, src, key, []byte{}, ECB, Pkcs5)
}

// TripleDesCBCPkcs7Encrypt CBC 加密模式
//
//	data要加密的数据，key要加密的密钥 PK5
func TripleDesCBCPkcs7Encrypt(data, key, iv []byte) ([]byte, error) {
	return Encrypt(TriDes, data, key, iv, CBC, Pkcs7)
}

// TripleDesCBCPkcs7Decrypt CBC 模式解密
//
//	src密文，key加密时的密钥
func TripleDesCBCPkcs7Decrypt(src, key, iv []byte) ([]byte, error) {
	return Decrypt(TriDes, src, key, iv, CBC, Pkcs7)
}

// TripleDesCFBPkcs7Encrypt CFB 加密模式
//
//	data要加密的数据，key要加密的密钥 PK5
func TripleDesCFBPkcs7Encrypt(data, key, iv []byte) ([]byte, error) {
	return Encrypt(TriDes, data, key, iv, CFB, Pkcs7)
}

// TripleDesCFBPkcs7Decrypt CFB 模式解密
//
//	src密文，key加密时的密钥
func TripleDesCFBPkcs7Decrypt(src, key, iv []byte) ([]byte, error) {
	return Decrypt(TriDes, src, key, iv, CFB, Pkcs7)
}

// TripleDesOFBPkcs7Encrypt OFB 加密模式
//
//	data要加密的数据，key要加密的密钥 PK5
func TripleDesOFBPkcs7Encrypt(data, key, iv []byte) ([]byte, error) {
	return Encrypt(TriDes, data, key, iv, OFB, Pkcs7)
}

// TripleDesOFBPkcs7Decrypt OFB 模式解密
//
//	src密文，key加密时的密钥
func TripleDesOFBPkcs7Decrypt(src, key, iv []byte) ([]byte, error) {
	return Decrypt(TriDes, src, key, iv, OFB, Pkcs7)
}

// TripleDesCTRPkcs7Encrypt CTR 加密模式
//
//	data要加密的数据，key要加密的密钥 PK5
func TripleDesCTRPkcs7Encrypt(data, key, iv []byte) ([]byte, error) {
	return Encrypt(TriDes, data, key, iv, CTR, Pkcs7)
}

// TripleDesCTRPkcs7Decrypt CTR 模式解密
//
//	src密文，key加密时的密钥
func TripleDesCTRPkcs7Decrypt(src, key, iv []byte) ([]byte, error) {
	return Decrypt(TriDes, src, key, iv, CTR, Pkcs7)
}
