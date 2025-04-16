package gmSm

import (
	"crypto/rand"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"go-tools/encryption/gmSm/sm2"
	"go-tools/encryption/gmSm/sm3"
	"go-tools/encryption/gmSm/sm4"
	"go-tools/encryption/gmSm/x509"
	smx509 "go-tools/encryption/gmSm/x509"
	"io"
	"math/big"
	"os"
	"strings"
)

var verifySignFail = errors.New("验签失败")
var pubKeyIsEmptyErr = errors.New("公钥不能为空")
var priKeyIsEmptyErr = errors.New("私钥不能为空")

// 密文编码方式：
//
//	gmSm.HandleTypeHex-转为16进制编码；gmSm.HandleTypeBase64-转为base64编码
const (
	HandleTypeHex = iota
	HandleTypeBase64
)

// SM2非对称加密的结果由C1,C2,C3三部分组成。其中C1是生成随机数的计算出的椭圆曲线点，C2是密文数据，C3是SM3的摘要值。最开始的国密标准的结果是按C1C2C3顺序的，新标准的是按C1C3C2顺序存放的
const (
	C1C3C2 = iota
	C1C2C3 = 1
)

type GmSm struct {
	pubKey         *sm2.PublicKey  // 公钥
	priKey         *sm2.PrivateKey // 私钥
	uid            string          // 用户身份标识UID
	mode           int             // 国密标准（密文数据顺序），旧标准按C1C2C3顺序存放；新标准按C1C3C2顺序存放
	dataHandleType int             // 数据处理方式，HandleTypeBase64对结果进行base64编码；HandleTypeHex对结果进行16进制编码
}

type sm2Signature struct {
	R, S *big.Int
}

type Option func(sm *GmSm)

// WithModeAndHandleType mode、dataHandleType、uid
//
//	mode（国密标准/密文数据顺序） 可选值参考：旧标准按 gmSm.C1C2C3 顺序存放；新标准按 gmSm.C1C3C2 顺序存放
//	dataHandleType（密文的编码方式）可选值参考：gmSm.HandleTypeBase64（对结果进行base64编码）；gmSm.HandleTypeHex（对结果进行16进制编码）
//	uid（用户身份标识）无特殊约定的情况下，用户身份标识 ID 的长度为 16 字节，如不填写将采用默认的标识ID（1234567812345678）
func WithModeAndHandleType(mode, dataHandleType int, uid ...string) Option {
	return func(sm *GmSm) {
		sm.mode = mode
		sm.dataHandleType = dataHandleType
		if len(uid) > 0 {
			sm.uid = uid[0]
		}
	}
}

// LoadSm2PublicPrivateKeyFromFile 从文件中读取sm2的公私钥对象
//
//	pubFile：sm2公钥文件pem格式；priFile：sm2私钥文件pem格式；pwd：私钥文件密码，如果没有则为nil
func LoadSm2PublicPrivateKeyFromFile(pubFile, priFile string, pwd []byte, options ...Option) (*GmSm, error) {
	gmSm := &GmSm{}
	//从文件读取公钥
	pubData, err := os.ReadFile(pubFile)
	if err != nil {
		return nil, err
	}
	gmSm.pubKey, err = smx509.ReadPublicKeyFromPem(pubData)
	if err != nil {
		err = errors.New(fmt.Sprintf("LoadSm2PublicPrivateKeyFromFile gmx509.ReadPublicKeyFromPem read failed, error: %s", err.Error()))
		return nil, err
	}

	//从文件读取私钥
	priData, err := os.ReadFile(priFile)
	if err != nil {
		return nil, err
	}
	gmSm.priKey, err = smx509.ReadPrivateKeyFromPem(priData, pwd)
	if err != nil {
		err = errors.New(fmt.Sprintf("LoadSm2PublicPrivateKeyFromFile gmx509.ReadPrivateKeyFromPem read failed, error: %s", err.Error()))
		return nil, err
	}

	for _, option := range options {
		option(gmSm)
	}

	return gmSm, err
}

// LoadSm2PublicKeyFromFile 从文件中读取sm2的公钥对象
//
//	pubFile：sm2公钥文件pem格式；
func LoadSm2PublicKeyFromFile(pubFile string, options ...Option) (*GmSm, error) {
	gmSm := &GmSm{}

	//从文件读取公钥
	pubData, err := os.ReadFile(pubFile)
	if err != nil {
		return nil, err
	}

	gmSm.pubKey, err = x509.ReadPublicKeyFromPem(pubData)
	if err != nil {
		err = errors.New(fmt.Sprintf("LoadSm2PublicPrivateKeyFromFile gmx509.ReadPublicKeyFromPem read failed, error: %s", err.Error()))
		return nil, err
	}

	for _, option := range options {
		option(gmSm)
	}

	return gmSm, err
}

// LoadSm2PrivateKeyFromFile 从文件中读取sm2的私钥对象
//
//	priFile：sm2私钥文件pem格式；pwd：私钥文件密码，如果没有则为nil
func LoadSm2PrivateKeyFromFile(priFile string, pwd []byte, options ...Option) (*GmSm, error) {
	gmSm := &GmSm{}

	//从文件读取私钥
	priData, err := os.ReadFile(priFile)
	if err != nil {
		return nil, err
	}
	gmSm.priKey, err = x509.ReadPrivateKeyFromPem(priData, pwd)
	if err != nil {
		err = errors.New(fmt.Sprintf("LoadSm2PublicPrivateKeyFromFile gmx509.ReadPrivateKeyFromPem read failed, error: %s", err.Error()))
		return nil, err
	}

	for _, option := range options {
		option(gmSm)
	}

	return gmSm, err
}

// LoadSm2PublicPrivateKeyFromHex 从sm2标准公私钥中读取公私钥对象
//
//	pubHex：sm2标准公钥（十六进制编码）；priHex：sm2标准私钥（十六进制编码）
func LoadSm2PublicPrivateKeyFromHex(pubHex, priHex string, options ...Option) (*GmSm, error) {
	gmSm := &GmSm{}

	pubKeyLen := len(pubHex)
	if pubKeyLen == 0 {
		return nil, pubKeyIsEmptyErr
	}

	if pubKeyLen == 130 && strings.HasPrefix(pubHex, "04") { // 这里需要去除开头的04
		pubHex = pubHex[2:]
	}

	pubKey, err := x509.ReadPublicKeyFromHex(pubHex)
	if err != nil {
		err = errors.New(fmt.Sprintf("LoadSm2PublicPrivateKeyFromHex gmx509.ReadPublicKeyFromHex read failed, error: %s", err.Error()))
		return nil, err
	}

	priKey, err := x509.ReadPrivateKeyFromHex(priHex)
	if err != nil {
		err = errors.New(fmt.Sprintf("LoadSm2PublicPrivateKeyFromHex gmx509.ReadPrivateKeyFromHex read failed, error: %s", err.Error()))
		return nil, err
	}

	for _, option := range options {
		option(gmSm)
	}

	gmSm.pubKey = pubKey
	gmSm.priKey = priKey
	return gmSm, err
}

// LoadSm2PublicKeyFromHex 从sm2标准公钥中读取公钥对象
//
//	pubHex：sm2标准公钥（十六进制编码）
func LoadSm2PublicKeyFromHex(pubHex string, options ...Option) (*GmSm, error) {
	gmSm := &GmSm{}

	pubKeyLen := len(pubHex)
	if pubKeyLen == 0 {
		return nil, pubKeyIsEmptyErr
	}

	if pubKeyLen == 130 && strings.HasPrefix(pubHex, "04") { // 这里需要去除开头的04
		pubHex = pubHex[2:]
	}

	pubKey, err := x509.ReadPublicKeyFromHex(pubHex)
	if err != nil {
		err = errors.New(fmt.Sprintf("LoadSm2PublicKeyFromHex gmx509.ReadPublicKeyFromHex read failed, error: %s", err.Error()))
		return nil, err
	}

	for _, option := range options {
		option(gmSm)
	}

	gmSm.pubKey = pubKey
	return gmSm, err
}

// LoadSm2PrivateKeyFromHex 从sm2标准私钥中读取私钥对象
//
//	priHex：sm2标准私钥（十六进制编码）
func LoadSm2PrivateKeyFromHex(priHex string, options ...Option) (*GmSm, error) {
	gmSm := &GmSm{}

	priKeyLen := len(priHex)
	if priKeyLen == 0 {
		return nil, priKeyIsEmptyErr
	}

	priKey, err := x509.ReadPrivateKeyFromHex(priHex)
	if err != nil {
		err = errors.New(fmt.Sprintf("LoadSm2PublicPrivateKeyFromHex gmx509.ReadPrivateKeyFromHex read failed, error: %s", err.Error()))
		return nil, err
	}

	for _, option := range options {
		option(gmSm)
	}

	gmSm.priKey = priKey
	return gmSm, err
}

// GenerateHexPubPri 随机生成十六进制编码的公私钥
//
//	返回值说明：pubHex-sm2公钥（ 默认生成公钥 130 位），以04开头，但是大部分情况下在使用时需要去除开头的04，不同语言有所差异
func GenerateHexPubPri(randoms ...io.Reader) (pubHex, priHex string, err error) {
	random := rand.Reader
	if len(randoms) > 0 {
		random = randoms[0]
	}
	pri, er := sm2.GenerateKey(random)
	if er != nil {
		err = er
		return
	}
	pubHex = x509.WritePublicKeyToHex(&pri.PublicKey)
	priHex = x509.WritePrivateKeyToHex(pri)

	////bytes := pri.PublicKey.X.Bytes()
	////bytes = append(bytes, pri.PublicKey.Y.Bytes()...)
	////bytes = append([]byte{0x04}, bytes...)
	////fmt.Println(pubHex)
	//r, _ := hex.DecodeString(pubHex)
	//r2 := base64.StdEncoding.EncodeToString(r)
	//
	//fmt.Println(r2)

	//pubPemBytes, _ := x509.WritePublicKeyToPem(&pri.PublicKey)
	//priPemBytes, _ := x509.WritePrivateKeyToPem(pri, nil)
	//
	//fmt.Println(string(pubPemBytes))
	//fmt.Println(string(priPemBytes))

	return
}

// Sm2Encrypt sm2加密
//
//	data：待加密数据
func (g *GmSm) Sm2Encrypt(data string) (string, error) {
	cipherText, err := sm2.Encrypt(g.pubKey, []byte(data), rand.Reader, g.mode)
	if err != nil {
		return "", err
	}

	var result string
	switch g.dataHandleType {
	case HandleTypeBase64:
		result = base64.StdEncoding.EncodeToString(cipherText)
	case HandleTypeHex:
		result = hex.EncodeToString(cipherText)
	}
	return result, nil
}

// Sm2Decrypt sm2解密
//
//	data：加密数据；
func (g *GmSm) Sm2Decrypt(data string) (string, error) {
	var dataDecode []byte
	switch g.dataHandleType {
	case HandleTypeBase64:
		dataDecode, _ = base64.StdEncoding.DecodeString(data)
	case HandleTypeHex:
		dataDecode, _ = hex.DecodeString(data)
	}

	plainText, err := sm2.Decrypt(g.priKey, dataDecode, g.mode)
	if err != nil {
		return "", err
	}

	var result string
	switch g.dataHandleType {
	case HandleTypeBase64:
		result = string(plainText)
	case HandleTypeHex:
		hds, _ := hex.DecodeString(hex.EncodeToString(plainText))
		result = string(hds)
	}

	return result, nil
}

// Sm2Sign sm2私钥签名
//
//	msg：原始数据；
func (g *GmSm) Sm2Sign(msg string) (string, error) {
	r, s, err := sm2.Sm2Sign(g.priKey, []byte(msg), []byte(g.uid), rand.Reader)
	if err != nil {
		return "", err
	}
	data, err := asn1.Marshal(sm2Signature{r, s})
	if err != nil {
		return "", err
	}

	var result string
	switch g.dataHandleType {
	case HandleTypeBase64:
		result = base64.StdEncoding.EncodeToString(data)
	case HandleTypeHex:
		result = hex.EncodeToString(data)
	}
	return result, nil
}

// Sm2SignVerify sm2公钥验签
//
//	msg：原始数据；sign：签名串
func (g *GmSm) Sm2SignVerify(msg, sign string) error {
	var signDecode []byte
	switch g.dataHandleType {
	case HandleTypeBase64:
		signDecode, _ = base64.StdEncoding.DecodeString(sign)
	case HandleTypeHex:
		signDecode, _ = hex.DecodeString(sign)
	}

	var sm2Sign sm2Signature
	_, err := asn1.Unmarshal(signDecode, &sm2Sign)
	if err != nil {
		return err
	}

	if !sm2.Sm2Verify(g.pubKey, []byte(msg), []byte(g.uid), sm2Sign.R, sm2Sign.S) {
		return verifySignFail
	}
	return nil
}

// Sm3Digest Sm3摘要
//
//	rawData：原始数据
func Sm3Digest(rawData string) string {
	hash1 := sm3.Sm3Sum([]byte(rawData))
	hashHex := hex.EncodeToString(hash1[:])
	return hashHex
}

// Sm3DigestVerify sm3摘要验证
//
//	rawData：原始数据；digest：待验证的摘要
func Sm3DigestVerify(rawData, digest string) error {
	sm3Digest := Sm3Digest(rawData)
	if digest != sm3Digest {
		return verifySignFail
	}
	return nil
}

// SetSm4IV 设置SM4算法实现的IV值,不设置则使用默认值
func SetSm4IV(iv []byte) error {
	return sm4.SetIV(iv)
}

// Sm4Cbc sm4 Cbc模式
//
//	key：密钥，如果是16进制的密钥需要hex.DecodeString再传入；in： 待加密字符串；mode：true-加密、false-解密
func Sm4Cbc(key []byte, in []byte, mode bool) (out []byte, err error) {
	return sm4.Sm4Cbc(key, in, mode)
}

// Sm4Ecb sm4 Ecb模式
//
//	key：密钥，如果是16进制的密钥需要hex.DecodeString再传入；in： 待加密字符串；mode：true-加密、false-解密
func Sm4Ecb(key []byte, in []byte, mode bool) (out []byte, err error) {
	return sm4.Sm4Ecb(key, in, mode)
}

// Sm4CFB sm4 Cfb模式
//
//	key：密钥，如果是16进制的密钥需要hex.DecodeString再传入；in： 待加密字符串；mode：true-加密、false-解密
func Sm4CFB(key []byte, in []byte, mode bool) (out []byte, err error) {
	return sm4.Sm4CFB(key, in, mode)
}

// Sm4OFB sm4 Ofb模式
//
//	key：密钥，如果是16进制的密钥需要hex.DecodeString再传入；in： 待加密字符串；mode：true-加密、false-解密
func Sm4OFB(key []byte, in []byte, mode bool) (out []byte, err error) {
	return sm4.Sm4OFB(key, in, mode)
}
