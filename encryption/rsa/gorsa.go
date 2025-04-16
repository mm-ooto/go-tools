package gorsa

import (
	"bytes"
	"crypto"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"go-tools/utils"
	"io"
	"os"
	"strings"
)

var (
	ErrPriKeyPasswordIsEmpty = errors.New("private key password is empty")
	ErrPubKeyIsEmpty         = errors.New(`please set the public key in advance`)
	ErrPriKeyIsEmpty         = errors.New(`please set the private key in advance`)
)

type DataHandleType int

// 编码方式：0：转为16进制编码；1：转为base64编码
const (
	HandleTypeBase64 DataHandleType = iota // base64编码
	HandleTypeHex                          // 十六进制编码
)

var GRsa = &GoRsa{}

type GoRsa struct {
	pubKey *rsa.PublicKey  // 公钥
	priKey *rsa.PrivateKey // 私钥
}

// SetPublicKeyAndPriKeyWithRSA 设置公钥和私钥
func (gr *GoRsa) SetPublicKeyAndPriKeyWithRSA(pubKey *rsa.PublicKey, priKey *rsa.PrivateKey) *GoRsa {

	return &GoRsa{
		pubKey: pubKey,
		priKey: priKey,
	}
}

// NewGoRsaFromString 从公私、私钥字符串中初始化GoRsa
//
//	pubKeyStr：公钥字符串；priKeyStr：私钥字符串；isPemFormat：公私、私钥字符串是否是pem格式
func NewGoRsaFromString(pubKeyStr, priKeyStr string, isPemFormat bool) (*GoRsa, error) {

	if !isPemFormat {
		pubKeyStr = utils.GetPemPublic(pubKeyStr)
		priKeyStr = utils.GetPemPrivate(priKeyStr)
	}

	gr := &GoRsa{}

	pubKey, err := getPubKey([]byte(pubKeyStr))
	if err != nil {
		return nil, err
	}
	priKey, err := getPriKey([]byte(priKeyStr))
	if err != nil {
		return nil, err
	}

	gr.pubKey = pubKey
	gr.priKey = priKey

	return gr, nil
}

// NewGoRsaFromFile 从公私、私钥文件中初始化GoRsa
func NewGoRsaFromFile(pubKeyFile, priKeyFile string) (*GoRsa, error) {
	gr := &GoRsa{}

	pubKey, err := getPubKeyFromFile(pubKeyFile)
	if err != nil {
		return nil, err
	}
	priKey, err := getPriKeyFromFile(priKeyFile)
	if err != nil {
		return nil, err
	}

	gr.pubKey = pubKey
	gr.priKey = priKey
	return gr, nil
}

// SetSinglePubKeyFromFile 从公钥文件中，单独设置公钥
func SetSinglePubKeyFromFile(pubKeyFile string) (err error) {
	GRsa.pubKey, err = getPubKeyFromFile(pubKeyFile)
	if err != nil {
		return
	}
	return
}

// SetSinglePriKeyFromFile 从私钥文件中，单独设置私钥
func SetSinglePriKeyFromFile(priKeyFile string, password ...string) (err error) {

	if strings.HasSuffix(priKeyFile, ".pfx") {
		if len(password) == 0 {
			return ErrPriKeyPasswordIsEmpty
		}
		GRsa.priKey, err = getPriKeyFromPfxFile(priKeyFile, password[0])
		if err != nil {
			return
		}
	} else {
		GRsa.priKey, err = getPriKeyFromFile(priKeyFile)
		if err != nil {
			return
		}
	}
	return
}

// SetSinglePublicKeyFromCert 从证书文件中中获取公钥
//
//	certFilePath：公钥证书文件路径
func SetSinglePublicKeyFromCert(certFilePath string) error {

	bytes, err := os.ReadFile(certFilePath)
	if err != nil {
		return err
	}

	// 如果.cer内容是二进制的，需要转换一下
	if utils.DetectBinary(certFilePath) {
		temp := utils.FormatCertKey(base64.StdEncoding.EncodeToString(bytes))
		bytes = []byte(temp)
	}

	block, _ := pem.Decode(bytes)

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return err
	}
	GRsa.pubKey = cert.PublicKey.(*rsa.PublicKey)
	return nil
}

// PubKeyEncrypt 公钥加密
func (gr *GoRsa) PubKeyEncrypt(input []byte, dataHandleType DataHandleType) (string, error) {
	if gr.pubKey == nil {
		return "", ErrPubKeyIsEmpty
	}
	output := bytes.NewBuffer(nil)
	err := pubKeyIO(gr.pubKey, bytes.NewReader(input), output, true)
	if err != nil {
		return "", err
	}

	byteData, err := io.ReadAll(output)
	if err != nil {
		return "", err
	}

	encodeFuncs := map[DataHandleType]func([]byte) string{
		HandleTypeHex:    hex.EncodeToString,
		HandleTypeBase64: base64.StdEncoding.EncodeToString,
	}

	encodeFunc, ok := encodeFuncs[dataHandleType]
	if !ok {
		return "", errors.New("unsupported encoding type")
	}

	result := encodeFunc(byteData)

	return result, nil
}

// PubKeyDecrypt 公钥解密
func (gr *GoRsa) PubKeyDecrypt(input []byte, dataHandleType DataHandleType) (string, error) {
	decodeFuncs := map[DataHandleType]func(string) ([]byte, error){
		HandleTypeHex:    hex.DecodeString,
		HandleTypeBase64: base64.StdEncoding.DecodeString,
	}

	decodeFunc, ok := decodeFuncs[dataHandleType]
	if !ok {
		return "", errors.New("unsupported decoding type")
	}

	decodeData, err := decodeFunc(string(input))
	if err != nil {
		return "", err
	}

	if gr.pubKey == nil {
		return "", ErrPubKeyIsEmpty
	}
	output := bytes.NewBuffer(nil)
	err = pubKeyIO(gr.pubKey, bytes.NewReader(decodeData), output, false)
	if err != nil {
		return "", err
	}

	byteData, err := io.ReadAll(output)
	if err != nil {
		return "", err
	}

	return string(byteData), nil
}

// PriKeyEncrypt 私钥加密
func (gr *GoRsa) PriKeyEncrypt(input []byte, dataHandleType DataHandleType) (string, error) {
	if gr.priKey == nil {
		return "", ErrPriKeyIsEmpty
	}
	output := bytes.NewBuffer(nil)
	err := priKeyIO(gr.priKey, bytes.NewReader(input), output, true)
	if err != nil {
		return "", err
	}

	byteData, err := io.ReadAll(output)
	if err != nil {
		return "", err
	}

	encodeFuncs := map[DataHandleType]func([]byte) string{
		HandleTypeHex:    hex.EncodeToString,
		HandleTypeBase64: base64.StdEncoding.EncodeToString,
	}

	encodeFunc, ok := encodeFuncs[dataHandleType]
	if !ok {
		return "", errors.New("unsupported encoding type")
	}

	result := encodeFunc(byteData)

	return result, nil
}

// PriKeyDecrypt 私钥解密
func (gr *GoRsa) PriKeyDecrypt(input []byte, dataHandleType DataHandleType) (string, error) {
	decodeFuncs := map[DataHandleType]func(string) ([]byte, error){
		HandleTypeHex:    hex.DecodeString,
		HandleTypeBase64: base64.StdEncoding.DecodeString,
	}

	decodeFunc, ok := decodeFuncs[dataHandleType]
	if !ok {
		return "", errors.New("unsupported decoding type")
	}

	decodeData, err := decodeFunc(string(input))
	if err != nil {
		return "", err
	}

	if gr.priKey == nil {
		return "", ErrPriKeyIsEmpty
	}
	output := bytes.NewBuffer(nil)
	err = priKeyIO(gr.priKey, bytes.NewReader(decodeData), output, false)
	if err != nil {
		return "", err
	}

	byteData, err := io.ReadAll(output)
	if err != nil {
		return "", err
	}

	return string(byteData), nil
}

// SignShaXWithRSA Rsa签名
//
// signStr：待签名字符串；hash：哈希类型（目前支持SHA256、SHA1、MD5）；
// signatureEncodeType：签名编码方式（可选值：gorsa.HandleTypeHex、gorsa.HandleTypeBase64），默认为 gorsa.HandleTypeBase64
func (gr *GoRsa) SignShaXWithRSA(data string, hash crypto.Hash, signatureEncodeType ...DataHandleType) (string, error) {
	hashFuncs := map[crypto.Hash]func([]byte) []byte{
		crypto.SHA256: func(data []byte) []byte { h := sha256.Sum256(data); return h[:] },
		crypto.SHA1:   func(data []byte) []byte { h := sha1.Sum(data); return h[:] },
		crypto.MD5:    func(data []byte) []byte { h := md5.Sum(data); return h[:] },
	}

	hashFunc, ok := hashFuncs[hash]
	if !ok {
		return "", errors.New("unsupported hash type")
	}

	hashed := hashFunc([]byte(data))

	signatureByte, err := rsa.SignPKCS1v15(rand.Reader, gr.priKey, hash, hashed[:])
	if err != nil {
		return "", err
	}

	encodeType := HandleTypeBase64
	if len(signatureEncodeType) > 0 {
		encodeType = signatureEncodeType[0]
	}

	encodeFuncs := map[DataHandleType]func([]byte) string{
		HandleTypeHex:    hex.EncodeToString,
		HandleTypeBase64: base64.StdEncoding.EncodeToString,
	}

	encodeFunc, ok := encodeFuncs[encodeType]
	if !ok {
		return "", errors.New("unsupported encoding type")
	}

	signature := encodeFunc(signatureByte)

	return signature, nil
}

// VerifySignShaWithRsa Rsa验签
//
// signingStr：待签名字符串；signature：要验证的签名字符串；hash：哈希类型（目前支持SHA256、SHA1、MD5）；
// signatureDecodeType：签名解码方式（可选值：gorsa.HandleTypeHex、gorsa.HandleTypeBase64），默认为 gorsa.HandleTypeBase64
func (gr *GoRsa) VerifySignShaWithRsa(signingStr, signature string, hash crypto.Hash, signatureDecodeType ...DataHandleType) (err error) {

	hashFuncs := map[crypto.Hash]func([]byte) []byte{
		crypto.SHA256: func(data []byte) []byte { h := sha256.Sum256(data); return h[:] },
		crypto.SHA1:   func(data []byte) []byte { h := sha1.Sum(data); return h[:] },
		crypto.MD5:    func(data []byte) []byte { h := md5.Sum(data); return h[:] },
	}

	hashed, ok := hashFuncs[hash]
	if !ok {
		return errors.New("unsupported hash type")
	}

	encodeType := HandleTypeBase64
	if len(signatureDecodeType) > 0 {
		encodeType = signatureDecodeType[0]
	}

	decodeFuncs := map[DataHandleType]func(string) ([]byte, error){
		HandleTypeHex:    hex.DecodeString,
		HandleTypeBase64: base64.StdEncoding.DecodeString,
	}

	signatureDecodeByte, err := decodeFuncs[encodeType](signature)
	if err != nil {
		return err
	}

	return rsa.VerifyPKCS1v15(gr.pubKey, hash, hashed([]byte(signingStr)), signatureDecodeByte)
}
