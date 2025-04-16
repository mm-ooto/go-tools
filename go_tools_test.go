package go_tools

import (
	"crypto"
	"go-tools/encryption/gmSm"
	gmx509 "go-tools/encryption/gmSm/x509"
	goaesdes "go-tools/encryption/go-aes-des"
	gorsa "go-tools/encryption/rsa"
	"go-tools/pdf/detectXss"
	"go-tools/utils"
	"os"

	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	gmsm2 "go-tools/encryption/gmSm/sm2"
	gmsm3 "go-tools/encryption/gmSm/sm3"
	gmsm4 "go-tools/encryption/gmSm/sm4"
	"strings"
	"testing"

	"github.com/ZZMarquis/gm/sm2"
	"github.com/ZZMarquis/gm/sm3"
)

//>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>utils begin>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

func TestNumberConvertUpper(t *testing.T) {
	tests := []struct {
		amount   float64
		isRound  bool
		expected string
	}{
		{2784.64, true, "贰仟柒佰捌拾肆圆陆角肆分"},
		{2784.64, false, "贰仟柒佰捌拾肆圆陆角"},
		{0, true, "零"},
		{-1234.56, true, "负壹仟贰佰叁拾肆圆伍角陆分"},
		{100000000, true, "壹亿元"},
		{100100000, true, "壹亿零壹拾万元"},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%v_%t", tt.amount, tt.isRound), func(t *testing.T) {
			result := utils.NumberConvertUpper(tt.amount, tt.isRound)
			if result != tt.expected {
				t.Errorf("NumberConvertUpper(%v, %t) = %s; want %s", tt.amount, tt.isRound, result, tt.expected)
			} else {
				fmt.Printf("Test passed: %v -> %s\n", tt.amount, result)
			}
		})
	}
}

func TestGenerateRSAKey_StandardBits(t *testing.T) {
	err := utils.GenerateRSAKey("./testdata/private_2048.pem", "./testdata/public_2048.pem", 2048)
	if err != nil {
		t.Fatalf("生成失败: %v", err)
	}
	t.Log("ok")
}

func TestGenerateBatchUpdateSQL(t *testing.T) {
	data := []map[string]interface{}{
		{"id": 1, "name": "Alice", "age": 25, "email": "alice@example.com"},
		{"id": 2, "name": "Bob's", "age": 30, "email": "bob@example.com"},
		{"id": 3, "name": "Charlie", "age": 28, "email": nil},
	}
	// 无附加条件
	sql1, _ := utils.GenerateBatchUpdateSQL("users", data, "id")
	fmt.Println("SQL1:\n", sql1)
	//UPDATE `users`
	//SET
	//    `email` = CASE `id` WHEN 1 THEN 'alice@example.com' WHEN 2 THEN 'bob@example.com' WHEN 3 THEN NULL END,
	//    `name` = CASE `id` WHEN 1 THEN 'Alice' WHEN 2 THEN 'Bob''s' WHEN 3 THEN 'Charlie' END,
	//    `age` = CASE `id` WHEN 1 THEN 25 WHEN 2 THEN 30 WHEN 3 THEN 28 END
	//WHERE `id` IN (1, 2, 3);

	// 附加单个条件
	sql2, _ := utils.GenerateBatchUpdateSQL("users", data, "id", "status = 'active'")
	fmt.Println("\nSQL2:\n", sql2)
	//	UPDATE `users`
	//SET
	//    `name` = CASE `id` WHEN 1 THEN 'Alice' WHEN 2 THEN 'Bob''s' WHEN 3 THEN 'Charlie' END,
	//    `age` = CASE `id` WHEN 1 THEN 25 WHEN 2 THEN 30 WHEN 3 THEN 28 END,
	//    `email` = CASE `id` WHEN 1 THEN 'alice@example.com' WHEN 2 THEN 'bob@example.com' WHEN 3 THEN NULL END
	//WHERE `id` IN (2, 3, 1) AND (status = 'active');

	// 附加多个条件
	sql3, _ := utils.GenerateBatchUpdateSQL("users", data, "id",
		"created_at > '2025-01-01'",
		"department_id IN (10,20)")
	fmt.Println("\nSQL3:\n", sql3)
	//UPDATE `users`
	//SET
	//    `email` = CASE `id` WHEN 1 THEN 'alice@example.com' WHEN 2 THEN 'bob@example.com' WHEN 3 THEN NULL END,
	//    `name` = CASE `id` WHEN 1 THEN 'Alice' WHEN 2 THEN 'Bob''s' WHEN 3 THEN 'Charlie' END,
	//    `age` = CASE `id` WHEN 1 THEN 25 WHEN 2 THEN 30 WHEN 3 THEN 28 END
	//WHERE `id` IN (1, 2, 3) AND (created_at > '2025-01-01') AND (department_id IN (10,20));
}

//>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>utils end>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

//>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>pdf begin>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

func TestDetectPDFXSSFromPath(t *testing.T) {
	err := detectXss.DetectPDFXSS("./testdata/detectPDFXSS/xss_js.pdf")
	t.Log(err) // 检测到PDF文件包含XSS漏洞风险，可能存在JavaScript注入攻击

	err = detectXss.DetectPDFXSS("./testdata/detectPDFXSS/empty.pdf")
	t.Log(err) // <nil>
}

func TestDetectPDFXSSFromFileByte(t *testing.T) {
	fileByte, _ := os.ReadFile("./testdata/detectPDFXSS/xss_js.pdf")
	err := detectXss.DetectPDFXSS(fileByte) // 检测到PDF文件包含XSS漏洞风险，可能存在JavaScript注入攻击
	t.Log(err)

	fileByte, _ = os.ReadFile("./testdata/detectPDFXSS/empty.pdf")
	err = detectXss.DetectPDFXSS(fileByte) // <nil>
	t.Log(err)
}

//>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>pdf end>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

//>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>sm begin>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

func TestSm2EncryptAndDecrypt1(t *testing.T) {
	pub := "d618186f66a02cc61dd0beafc5d689d7b541a41eb0b629d7dd563d7ea361b5ab8593d928aa3c49d20c536ad31043042f2cb8d596f145e1983585eb8c23e80df9"
	pri := "4ecc667b8d4ba0167b5a64cb0ea5bc44dc1f9945352f88482da63288eeb8063e"
	gm, err := gmSm.LoadSm2PublicPrivateKeyFromHex(pub, pri, gmSm.WithModeAndHandleType(gmSm.C1C2C3, gmSm.HandleTypeBase64, "123"))
	if err != nil {
		t.Log(err.Error())
		return
	}
	Sm2EncryptAndDecrypt(gm, "HELLO WORLD")
}

func TestLoadSm2PrivateKeyFromHexAndLoadSm2PublicKeyFromHex(t *testing.T) {
	pub := "042A23C0D1D10391D0A187854C6210655F7FEF506A3D94C1F5331AC33933A3F1476B483B77E4D6CE26C11D94CB63DB3BBE8EDDC1A92E89007B0E83E1473B5E5045"
	pri := "4ecc667b8d4ba0167b5a64cb0ea5bc44dc1f9945352f88482da63288eeb8063e"

	gm, err := gmSm.LoadSm2PublicKeyFromHex(pub, gmSm.WithModeAndHandleType(gmSm.C1C2C3, gmSm.HandleTypeHex, "123"))
	if err != nil {
		t.Log(err.Error())
		return
	}

	msg := "HELLO WORLD"
	encData, err := gm.Sm2Encrypt(msg)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	fmt.Println("sm2加密结果：", encData)

	gm, err = gmSm.LoadSm2PrivateKeyFromHex(pri, gmSm.WithModeAndHandleType(gmSm.C1C2C3, gmSm.HandleTypeHex, "123"))
	if err != nil {
		t.Log(err.Error())
		return
	}

	decrData, err := gm.Sm2Decrypt(encData)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	fmt.Println("sm2解密结果：", decrData)
}

func TestSm2EncryptAndDecrypt2(t *testing.T) {
	pub := "./testdata/sm2_pub_key.pem"
	pri := "./testdata/sm2_pri_key_pkcs8.pem"
	gm, err := gmSm.LoadSm2PublicPrivateKeyFromFile(pub, pri, nil, gmSm.WithModeAndHandleType(gmSm.C1C3C2, gmSm.HandleTypeBase64, "123"))
	if err != nil {
		t.Log(err.Error())
		return
	}
	Sm2EncryptAndDecrypt(gm, "HELLO WORLD")
}

func TestLoadSm2PublicKeyFromFileAndLoadSm2PrivateKeyFromFile(t *testing.T) {
	pubFile := "./testdata/sm2_pub_key.pem"
	priFile := "./testdata/sm2_pri_key_pkcs8.pem"
	gm, err := gmSm.LoadSm2PublicKeyFromFile(pubFile, gmSm.WithModeAndHandleType(gmSm.C1C3C2, gmSm.HandleTypeBase64, "123"))
	if err != nil {
		t.Log(err.Error())
		return
	}
	msg := "HELLO WORLD"
	encData, err := gm.Sm2Encrypt(msg)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	fmt.Println("sm2加密结果：", encData)

	gm, err = gmSm.LoadSm2PrivateKeyFromFile(priFile, nil, gmSm.WithModeAndHandleType(gmSm.C1C3C2, gmSm.HandleTypeBase64, "123"))
	if err != nil {
		t.Log(err.Error())
		return
	}

	decrData, err := gm.Sm2Decrypt(encData)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	fmt.Println("sm2解密结果：", decrData)
}

func Sm2EncryptAndDecrypt(gm *gmSm.GmSm, msg string) {
	encData, err := gm.Sm2Encrypt(msg)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	fmt.Println("sm2加密结果：", encData)
	decrData, err := gm.Sm2Decrypt(encData)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	fmt.Println("sm2解密结果：", decrData)

	sign, err := gm.Sm2Sign(msg)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	fmt.Println("sm2签名：", sign)
	fmt.Println("sm2签名验证结果：", gm.Sm2SignVerify(msg, sign))

	digest := gmSm.Sm3Digest(msg)
	fmt.Println("sm3摘要：", digest)
	fmt.Println("sm3摘要验证结果：", gmSm.Sm3DigestVerify(msg, digest))
}

func TestGenerateHexPubPri(t *testing.T) {
	pubHex, priHex, err := gmSm.GenerateHexPubPri(rand.Reader)
	if err != nil {
		t.Log(err.Error())
		return
	}
	t.Log("pubHex：", pubHex)
	t.Log("priHex：", priHex)
}

func PubToBase64(pub *sm2.PublicKey) string {
	//pub.GetRawBytes()
	bytes := pub.X.Bytes()
	bytes = append(bytes, pub.Y.Bytes()...)
	pubHex := "3059301306072a8648ce3d020106082a811ccf5501822d03420004" + hex.EncodeToString(bytes)
	decode, _ := hex.DecodeString(pubHex)
	base64Pub := base64.StdEncoding.EncodeToString(decode)

	return base64Pub
}

func PriToBase64(pri *sm2.PrivateKey) string {
	//pri.GetRawBytes()
	bytes := pri.D.Bytes()
	priHex := "303d020100300b06072a8648ce3d02010500042b30290201010420" + hex.EncodeToString(bytes)
	decode, _ := hex.DecodeString(priHex)
	base64Pri := base64.StdEncoding.EncodeToString(decode)

	return base64Pri
}
func TestName33(t *testing.T) {

	str := "3059301306072a8648ce3d020106082a811ccf5501822d03420004"
	t.Log(str)
	decode, _ := hex.DecodeString(str)
	base64Pri := base64.StdEncoding.EncodeToString(decode)
	t.Log(base64Pri) // MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAE

	r1, _ := base64.StdEncoding.DecodeString(base64Pri)
	t.Log(hex.EncodeToString(r1), len(hex.EncodeToString(r1)))
	t.Log("------------------------------")

	r2, _ := base64.StdEncoding.DecodeString("MD0CAQAwCwYHKoZIzj0CAQUABCswKQIBAQQg")
	t.Log(hex.EncodeToString(r2), len(hex.EncodeToString(r2)))
	t.Log("------------------------------")

	decode, _ = hex.DecodeString("303d020100300b06072a8648ce3d02010500042b30290201010420 081bf780")
	base64Pri = base64.StdEncoding.EncodeToString(decode)
	t.Log(base64Pri)
	t.Log("------------------------------")
	// MD0CAQAwCwYHKoZIzj0CAQUABCswKQIBAQQg
	r1, _ = base64.StdEncoding.DecodeString("CBv3gA==")
	t.Log(hex.EncodeToString(r1), len(hex.EncodeToString(r1)))
}

func PriToHex(pri *sm2.PrivateKey) string {
	hex := hex.EncodeToString(pri.GetRawBytes())
	return hex
}

func PriToBase64Pub(pri *sm2.PrivateKey) string {
	pub := sm2.CalculatePubKey(pri)
	base64Pub := PubToBase64(pub)
	return base64Pub
}

func Generate() (string, string) {
	pri, pub, _ := sm2.GenerateKey(rand.Reader)
	return PriToHex(pri), PubToBase64(pub)
}

func HexToPri(priStr string) *sm2.PrivateKey {
	// 解码hex私钥
	privateKeyByte, _ := hex.DecodeString(priStr) // hex解码
	// 转成go版的私钥
	pri, err := sm2.RawBytesToPrivateKey(privateKeyByte)
	if err != nil {
		panic("私钥加载异常")
	}
	return pri
}
func Base64ToPub(pubStr string) *sm2.PublicKey {
	decode, _ := base64.StdEncoding.DecodeString(pubStr)
	pubHex := hex.EncodeToString(decode)
	fmt.Println("len=", len(pubHex), "pubHex=", pubHex)
	//pubHex = strings.ReplaceAll(pubHex, "3059301306072a8648ce3d020106082a811ccf5501822d03420004", "")
	pubHex = pubHex[len(pubHex)-128:]
	fmt.Println("len=", len(pubHex), "pubHex=", pubHex)
	pubByte, _ := hex.DecodeString(pubHex)
	pub, err := sm2.RawBytesToPublicKey(pubByte)
	if err != nil {
		fmt.Println("err=", err.Error())
		return nil
	}
	return pub
}

func Base64ToPri(priStr string) *sm2.PrivateKey {
	decode, _ := base64.StdEncoding.DecodeString(priStr)
	priHex := hex.EncodeToString(decode)
	fmt.Println("len=", len(priHex), "priHex=", priHex)
	priHex = priHex[len(priHex)-64:]
	fmt.Println("len=", len(priHex), "priHex=", priHex)
	priByte, _ := hex.DecodeString(priHex)
	pri, err := sm2.RawBytesToPrivateKey(priByte)
	if err != nil {
		fmt.Println(err.Error())
		return nil
	}
	return pri
}

func Sign(data string, userId []byte, pri *sm2.PrivateKey) string {
	signature, err := sm2.Sign(pri, userId, []byte(data))
	if err != nil {
		panic("云闪付签名错误")
	}
	// 转 base64
	sign := base64.StdEncoding.EncodeToString(signature)
	return sign
}

func Verify(data, sign string, userId []byte, pub *sm2.PublicKey) bool {
	sign1, _ := base64.StdEncoding.DecodeString(sign)
	return sm2.Verify(pub, userId, []byte(data), sign1)
}

func Test2(t *testing.T) {
	//生成密钥对
	hexPri, basePub := Generate()
	println("******* 生成 hex私钥：" + hexPri)
	println("******* 生成 base公钥：" + basePub)
	//Hex私钥转私钥对象
	pri := HexToPri(hexPri)
	//base64公钥转公钥对象
	pub := Base64ToPub(basePub)
	//私钥生成公钥
	base64Pub := PriToBase64Pub(pri)
	println("******* 私钥生成base64公钥：" + base64Pub)
	//私钥转hex
	priHex := PriToHex(pri)
	println("******* 私钥转hex：" + priHex)
	//公钥转base64
	pubBase := PubToBase64(pub)
	println("******* 公钥转base64：" + pubBase)
	//私钥转base64
	priBase := PriToBase64(pri)
	println("******* 私钥转base64：" + priBase)
	pri = Base64ToPri(priBase)
	//签名
	hashed := gmsm3.Sm3Sum([]byte(str))
	println("******* 签名hash：", hex.EncodeToString(hashed))
	sign := Sign("a=1", []byte("1"), pri)
	println("******* 签名：" + sign)
	//验签
	ver := Verify("a=1", sign, []byte("1"), pub)
	println(fmt.Sprintf("******* 验签：%t", ver))
}

func TestName444(t *testing.T) {
	base64Pub := "MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEDEz+qzBf2hKoMY5z8RJM5zCFTaGdcIOzy/IvF7vLtAcEE+rEimmNs/TRsOr5opotkkJ6DGxBqcYLOs6Fj0if+A=="
	//base64公钥转公钥对象
	pub := Base64ToPub(base64Pub)
	//公钥转base64
	pubBase := PubToBase64(pub)
	println(base64Pub)
	println("******* 公钥转base64：" + pubBase)

	//base64私钥转公钥对象
	pri := Base64ToPri("MD0CAQAwCwYHKoZIzj0CAQUABCswKQIBAQQgCBv3gL5P3DEXCxVCh78mtD4+aJnKwIVY8+Mc9cDOnVWgAgUA")
	//私钥转base64
	priBase := PriToBase64(pri)
	println("******* 私钥转base64：" + priBase)
	sign := Sign("a=1", []byte("1"), pri)
	println("******* 签名：" + sign)
	//验签
	ver := Verify("a=1", sign, []byte("1"), pub)
	println(fmt.Sprintf("******* 验签：%t", ver))
}

func TestName(t *testing.T) {
	javaHexPub := "04488CA51D03DCD0EB9CC61F4CDE2E91FA45D62D7480857B4CF50CF22D19EF92BA6AFF8F08DFF470B6B1516AA0BBFE6B3B06ACB88429061A108222C62D85E81C84" // 其它语言 16进制的sm2公钥
	if javaHexPub[:2] == "04" {
		javaHexPub = javaHexPub[2:] // 剔除开头04 转成golang要求的格式
	}

	decode, _ := hex.DecodeString(javaHexPub)
	base64Pub := base64.StdEncoding.EncodeToString(decode)

	javaHexPri := "00FAF63F43DC995F18D120036521E26D9511D49A59EA91940FC46B1CBB16C71168"
	decode2, _ := hex.DecodeString(javaHexPri)
	base64Pri := base64.StdEncoding.EncodeToString(decode2)

	msg := "[B@120d6fe6"
	pri := Base64ToPri(base64Pri)
	pub := Base64ToPub(base64Pub)
	priD := pri.D.String()

	println("******* dBigInteger：", priD)

	hash := sm3.Sum([]byte(str))
	println("******* 签名hash：", strings.ToUpper(hex.EncodeToString(hash[:])))

	sign := Sign(msg, nil, pri)
	println("******* 实际签名：" + sign)
	//验签
	ver := Verify(msg, sign, nil, pub)
	println(fmt.Sprintf("******* 验签：%t", ver))
}

var base64Pub = "MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEDEz+qzBf2hKoMY5z8RJM5zCFTaGdcIOzy/IvF7vLtAcEE+rEimmNs/TRsOr5opotkkJ6DGxBqcYLOs6Fj0if+A==" // base64格式的 sm2公钥
var base64Pri = "MD0CAQAwCwYHKoZIzj0CAQUABCswKQIBAQQgCBv3gL5P3DEXCxVCh78mtD4+aJnKwIVY8+Mc9cDOnVWgAgUA"                                         // base64格式的 sm2私钥
var str = "busines&certId=BANKTEST001&orderId=1669271981244&signType=SM2&txnTime=20221124063941&txnType=H5&version=1.0.1"
var base64Sign = "MEUCIQDrhsIHF5IQ8IKy1zsn2OY2ewWX20ecabkf2WRUBuYN6QIgSG9Q83Y1Ob5Jlp/FxbTaCnpbaewvHDK7D48a11H4v5s="

func Sm2Base64ToPub(base64Pub string) (pubKey *gmsm2.PublicKey, err error) {
	decode, _ := base64.StdEncoding.DecodeString(base64Pub)
	pubHex := hex.EncodeToString(decode)

	fmt.Println(pubHex)
	fmt.Println(pubHex[:len(pubHex)-128])
	pubHex = pubHex[len(pubHex)-128:]
	fmt.Println("hex公钥：", pubHex)
	pubKey, err = gmx509.ReadPublicKeyFromHex(pubHex)
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	fmt.Println("-----------------------------------------")
	return
}

func Sm2Base64ToPri(base64Pri string) (priKey *gmsm2.PrivateKey, err error) {
	decode, _ := base64.StdEncoding.DecodeString(base64Pri)
	priHex := hex.EncodeToString(decode)
	fmt.Println(priHex)
	fmt.Println(priHex[:len(priHex)-64])

	priHex = priHex[len(priHex)-64:]
	fmt.Println("hex私钥：", priHex)

	priKey, err = gmx509.ReadPrivateKeyFromHex(priHex)
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	return
}
func TestSm4Cbc(t *testing.T) {

	decoded, err := hex.DecodeString("2ed5da7ec7d7439196c78f23efc43292")
	if err != nil {
		t.Log(err.Error())
	}
	t.Log(string(decoded))
	data := []byte("95162010763P058|A2021011908888392185|1|20210119|20210119100101|2088002384487224")
	res1, err := gmsm4.Sm4Cbc(decoded, data, true)
	t.Log(err)
	t.Logf("%x", res1)
	t.Log("------------------------")

	res2, err := gmsm4.Sm4Cbc(decoded, res1, false)
	t.Log(err)
	t.Logf("%s", res2)
}

//>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>sm end>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

// >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>aes des begin>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
var key = "udik876ehjde32dU61edsxsf"
var data = "HELLO WORLD"

func TestTripleDesECBPkcs7EncryptAndDecrypt(t *testing.T) {
	bytes, err := goaesdes.TripleDesECBPkcs5Encrypt([]byte(data), []byte(key))
	if err != nil {
		t.Log(err.Error())
		return
	}
	t.Log("密文(hex):", goaesdes.HexEncode(bytes))
	t.Log("密文(base64):", goaesdes.Base64Encode(bytes))
	res, err := goaesdes.TripleDesECBPkcs5Decrypt(bytes, []byte(key))
	if err != nil {
		t.Log(err.Error())
		return
	}
	t.Log("解密结果:", string(res))
}

func TestTripleDesCBCPkcs7EncryptAndDecrypt(t *testing.T) {

	bytes, err := goaesdes.TripleDesCBCPkcs7Encrypt([]byte(data), []byte(key), []byte(""))
	if err != nil {
		t.Log(err.Error())
		return
	}
	t.Log("密文(hex):", goaesdes.HexEncode(bytes))
	t.Log("密文(base64):", goaesdes.Base64Encode(bytes))
	res, err := goaesdes.TripleDesCBCPkcs7Decrypt(bytes, []byte(key), []byte(""))
	if err != nil {
		t.Log(err.Error())
		return
	}
	t.Log("解密结果:", string(res))
}

func TestTripleDesCFBPkcs7EncryptAndDecrypt(t *testing.T) {

	bytes, err := goaesdes.TripleDesCFBPkcs7Encrypt([]byte(data), []byte(key), []byte(""))
	if err != nil {
		t.Log(err.Error())
		return
	}
	t.Log("密文(hex):", goaesdes.HexEncode(bytes))
	t.Log("密文(base64):", goaesdes.Base64Encode(bytes))
	res, err := goaesdes.TripleDesCFBPkcs7Decrypt(bytes, []byte(key), []byte(""))
	if err != nil {
		t.Log(err.Error())
		return
	}
	t.Log("解密结果:", string(res))
}

//>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>aes des end>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
//>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>gorsa begin>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

var goRsa *gorsa.GoRsa
var err error

var msg = "HELLO WORLD"

var pubKeyStr = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAk+89V7vpOj1rG6bTAKYM56qmFLwNCBVDJ3MltVVtxVUUByqc5b6u909MmmrLBqS//PWC6zc3wZzU1+ayh8xbUAEZuA3EjlPHIaFIVIz04RaW10+1xnby/RQE23tDqsv9a2jv/axjE/27b62nzvCWeItu1kNQ3MGdcuqKjke+LKhQ7nWPRCOd/ffVqSuRvG0YfUEkOz/6UpsPr6vrI331hWRB4DlYy8qFUmDsyvvExe4NjZWblXCqkEXRRAhi2SQRCl3teGuIHtDUxCskRIDiaMD+Qt2Yp+Vvbz6hUiqIWSIH1BoHJer/JOq2/O6X3cmuppU4AdVNgy8Bq236iXvrMQIDAQAB"
var priKeyStr = "MIIEpAIBAAKCAQEAk+89V7vpOj1rG6bTAKYM56qmFLwNCBVDJ3MltVVtxVUUByqc5b6u909MmmrLBqS//PWC6zc3wZzU1+ayh8xbUAEZuA3EjlPHIaFIVIz04RaW10+1xnby/RQE23tDqsv9a2jv/axjE/27b62nzvCWeItu1kNQ3MGdcuqKjke+LKhQ7nWPRCOd/ffVqSuRvG0YfUEkOz/6UpsPr6vrI331hWRB4DlYy8qFUmDsyvvExe4NjZWblXCqkEXRRAhi2SQRCl3teGuIHtDUxCskRIDiaMD+Qt2Yp+Vvbz6hUiqIWSIH1BoHJer/JOq2/O6X3cmuppU4AdVNgy8Bq236iXvrMQIDAQABAoIBAQCCbxZvHMfvCeg+YUD5+W63dMcq0QPMdLLZPbWpxMEclH8sMm5UQ2SRueGY5UBNg0WkC/R64BzRIS6pjkcrZQu95rp+heUgeM3C4SmdIwtmyzwEa8uiSY7Fhbkiq/Rly6aN5eB0kmJpZfa16S9kTszdTFNVp9TMUAo7IIE6IheT1x0WcX7aOWVqp9MDXBHV5T0Tvt8vFrPTldFgIuK45t3tr83tDcx53uC8cL5Ui8leWQjPh4BgdhJ3/MGTDWg+LW2vlAb4x+aLcDJMCH6Rcb1b8hs9iLTDkdVw9KirYQH5mbACXZyDEaqj1I2KamJIU2qDuTnKxNoc96HY2XMuSndhAoGBAMPwJuPuZqioJfNyS99x++ZTcVVwGRAbEvTvh6jPSGA0k3cYKgWRNnssMkHBzZa0p3/NmSwWc7LiL8whEFUDAp2ntvfPVJ19Xvm71gNUyCQ/hojqIAXytsNT1gBUTCMtFZmAkUsjqdM/hUnJMM9zH+w4lt5QM2y/YkCThoI65BVbAoGBAMFIGsIbnJDNhVap7HfWcYmGOlWgEEEchG6Uq6Lbai9T8c7xMSFc6DQiNMmQUAlgDaMVb6izPK4KGQaXMFt5h7hekZgkbxCKBd9xsLM72bWhM/nd/HkZdHQqrNAPFhY6/S8CIjRnRfdhsjBIA8K73yiUCsQlHAauGfPzdHET8ktjAoGAQdxeZi1DapuirhMUN9Zrkr8nkE1uz0AafiRpmC+cp2Hk05pWvapTAtIXTo0jWu38g3QLcYtWdqGa6WWPxNOPNIkkcmXJjmqO2yjtRg9gevazdSAlhXpRPpTWkSPEt+o2oXNa40PomK54UhYDhyeuakuXQsD4mCw4jXZJN0suUZMCgYAgzpBcKjulCH19fFI69RdIdJQqPIUFyEViT7HibsPTTLham+3u78oqLzQukmRDcx5ddCIDzIicMfKVf8whertivAqSfHytnf/pMW8AvUPy5G3iF5/nHj76CNRUbHsfQtv+wqnzoyPpHZgVQeQBhcoXJSm+qV3cdGjLU6OMHgqeaQKBgQCnmL5SX7GSAeB0rSNugPp2GezAQj0H4OCc8kNrHK8RUvXIU9B2zKA2z/QUKFb1gIGcKxYr+LqQ25/+TGvINjuf6P3fVkHL0U8jOG0IqpPJXO3Vl9B8ewWLcFQVB/nQfmaMa4ChK0QEUe+Mqi++MwgYbRHx1lIOXEfUJO+PXrMekw=="

var pubKeyPemStr = "-----BEGIN Public key-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAk+89V7vpOj1rG6bTAKYM\n56qmFLwNCBVDJ3MltVVtxVUUByqc5b6u909MmmrLBqS//PWC6zc3wZzU1+ayh8xb\nUAEZuA3EjlPHIaFIVIz04RaW10+1xnby/RQE23tDqsv9a2jv/axjE/27b62nzvCW\neItu1kNQ3MGdcuqKjke+LKhQ7nWPRCOd/ffVqSuRvG0YfUEkOz/6UpsPr6vrI331\nhWRB4DlYy8qFUmDsyvvExe4NjZWblXCqkEXRRAhi2SQRCl3teGuIHtDUxCskRIDi\naMD+Qt2Yp+Vvbz6hUiqIWSIH1BoHJer/JOq2/O6X3cmuppU4AdVNgy8Bq236iXvr\nMQIDAQAB\n-----END Public key-----"
var priKeyPemStr = "-----BEGIN Private key-----\nMIIEpAIBAAKCAQEAk+89V7vpOj1rG6bTAKYM56qmFLwNCBVDJ3MltVVtxVUUByqc\n5b6u909MmmrLBqS//PWC6zc3wZzU1+ayh8xbUAEZuA3EjlPHIaFIVIz04RaW10+1\nxnby/RQE23tDqsv9a2jv/axjE/27b62nzvCWeItu1kNQ3MGdcuqKjke+LKhQ7nWP\nRCOd/ffVqSuRvG0YfUEkOz/6UpsPr6vrI331hWRB4DlYy8qFUmDsyvvExe4NjZWb\nlXCqkEXRRAhi2SQRCl3teGuIHtDUxCskRIDiaMD+Qt2Yp+Vvbz6hUiqIWSIH1BoH\nJer/JOq2/O6X3cmuppU4AdVNgy8Bq236iXvrMQIDAQABAoIBAQCCbxZvHMfvCeg+\nYUD5+W63dMcq0QPMdLLZPbWpxMEclH8sMm5UQ2SRueGY5UBNg0WkC/R64BzRIS6p\njkcrZQu95rp+heUgeM3C4SmdIwtmyzwEa8uiSY7Fhbkiq/Rly6aN5eB0kmJpZfa1\n6S9kTszdTFNVp9TMUAo7IIE6IheT1x0WcX7aOWVqp9MDXBHV5T0Tvt8vFrPTldFg\nIuK45t3tr83tDcx53uC8cL5Ui8leWQjPh4BgdhJ3/MGTDWg+LW2vlAb4x+aLcDJM\nCH6Rcb1b8hs9iLTDkdVw9KirYQH5mbACXZyDEaqj1I2KamJIU2qDuTnKxNoc96HY\n2XMuSndhAoGBAMPwJuPuZqioJfNyS99x++ZTcVVwGRAbEvTvh6jPSGA0k3cYKgWR\nNnssMkHBzZa0p3/NmSwWc7LiL8whEFUDAp2ntvfPVJ19Xvm71gNUyCQ/hojqIAXy\ntsNT1gBUTCMtFZmAkUsjqdM/hUnJMM9zH+w4lt5QM2y/YkCThoI65BVbAoGBAMFI\nGsIbnJDNhVap7HfWcYmGOlWgEEEchG6Uq6Lbai9T8c7xMSFc6DQiNMmQUAlgDaMV\nb6izPK4KGQaXMFt5h7hekZgkbxCKBd9xsLM72bWhM/nd/HkZdHQqrNAPFhY6/S8C\nIjRnRfdhsjBIA8K73yiUCsQlHAauGfPzdHET8ktjAoGAQdxeZi1DapuirhMUN9Zr\nkr8nkE1uz0AafiRpmC+cp2Hk05pWvapTAtIXTo0jWu38g3QLcYtWdqGa6WWPxNOP\nNIkkcmXJjmqO2yjtRg9gevazdSAlhXpRPpTWkSPEt+o2oXNa40PomK54UhYDhyeu\nakuXQsD4mCw4jXZJN0suUZMCgYAgzpBcKjulCH19fFI69RdIdJQqPIUFyEViT7Hi\nbsPTTLham+3u78oqLzQukmRDcx5ddCIDzIicMfKVf8whertivAqSfHytnf/pMW8A\nvUPy5G3iF5/nHj76CNRUbHsfQtv+wqnzoyPpHZgVQeQBhcoXJSm+qV3cdGjLU6OM\nHgqeaQKBgQCnmL5SX7GSAeB0rSNugPp2GezAQj0H4OCc8kNrHK8RUvXIU9B2zKA2\nz/QUKFb1gIGcKxYr+LqQ25/+TGvINjuf6P3fVkHL0U8jOG0IqpPJXO3Vl9B8ewWL\ncFQVB/nQfmaMa4ChK0QEUe+Mqi++MwgYbRHx1lIOXEfUJO+PXrMekw==\n-----END Private key-----"

func TestNewGoRsaFromString(t *testing.T) {
	goRsa, err = gorsa.NewGoRsaFromString(pubKeyStr, priKeyStr, false)
	if err != nil {
		t.Log(err.Error())
		return
	}
	SignVerifySign(t, msg, crypto.SHA256)
	PubKeyEncryptPriKeyDecrypt(t, []byte(msg), gorsa.HandleTypeBase64)
	PriKeyEncryptPubKeyDecrypt(t, []byte(msg), gorsa.HandleTypeBase64)
}

func TestNewGoRsaFromStringIsPemFormat(t *testing.T) {
	goRsa, err = gorsa.NewGoRsaFromString(pubKeyPemStr, priKeyPemStr, true)
	if err != nil {
		t.Log(err.Error())
		return
	}
	SignVerifySign(t, msg, crypto.SHA256)
	PubKeyEncryptPriKeyDecrypt(t, []byte(msg), gorsa.HandleTypeBase64)
	PriKeyEncryptPubKeyDecrypt(t, []byte(msg), gorsa.HandleTypeBase64)
}

func TestNewGoRsaFromFile(t *testing.T) {
	goRsa, err = gorsa.NewGoRsaFromFile("./testdata/public_key.pem", "./testdata/private_key.pem")
	if err != nil {
		t.Log(err.Error())
		return
	}
	SignVerifySign(t, msg, crypto.SHA256)
	PubKeyEncryptPriKeyDecrypt(t, []byte(msg), gorsa.HandleTypeBase64)
	PriKeyEncryptPubKeyDecrypt(t, []byte(msg), gorsa.HandleTypeBase64)
}

func TestSetSinglePubKeyPriKeyFromFile(t *testing.T) {
	if err = gorsa.SetSinglePubKeyFromFile("./testdata/public_key.pem"); err != nil {
		t.Log(err.Error())
		return
	}
	if err = gorsa.SetSinglePriKeyFromFile("./testdata/private_key.pem"); err != nil {
		t.Log(err.Error())
		return
	}
	goRsa = gorsa.GRsa
	SignVerifySign(t, msg, crypto.SHA256)
	PubKeyEncryptPriKeyDecrypt(t, []byte(msg), gorsa.HandleTypeBase64)
	PriKeyEncryptPubKeyDecrypt(t, []byte(msg), gorsa.HandleTypeBase64)
}

func TestSetSinglePubKeyPriKeyFromCer(t *testing.T) {
	if err = gorsa.SetSinglePriKeyFromFile("./testdata/private.pfx", "123456"); err != nil {
		t.Log(err.Error())
		return
	}
	if err = gorsa.SetSinglePublicKeyFromCert("./testdata/public.cer"); err != nil {
		t.Log(err.Error())
		return
	}
	goRsa = gorsa.GRsa
	SignVerifySign(t, msg, crypto.MD5)
	PubKeyEncryptPriKeyDecrypt(t, []byte(msg), gorsa.HandleTypeBase64)
	PriKeyEncryptPubKeyDecrypt(t, []byte(msg), gorsa.HandleTypeBase64)
}

func SignVerifySign(t *testing.T, msg string, hash crypto.Hash) {
	t.Log("======================签名和验签======================")
	sign, err := goRsa.SignShaXWithRSA(msg, hash)
	if err != nil {
		t.Log(err)
		return
	}
	t.Log("签名：", sign)

	if err = goRsa.VerifySignShaWithRsa(msg, sign, hash); err != nil {
		t.Log(err)
		return
	}
	t.Log("验签成功")
}

func PriKeyEncryptPubKeyDecrypt(t *testing.T, input []byte, dataHandleType gorsa.DataHandleType) {
	t.Log("======================私钥加密和公钥解密======================")
	//
	data, err := goRsa.PriKeyEncrypt(input, dataHandleType)
	if err != nil {
		t.Log(err.Error())
		return
	}
	t.Log("加密结果：", data)
	//
	result, err := goRsa.PubKeyDecrypt([]byte(data), dataHandleType)
	if err != nil {
		t.Log(err.Error())
		return
	}
	t.Log("解密结果：", result)
}

func PubKeyEncryptPriKeyDecrypt(t *testing.T, input []byte, dataHandleType gorsa.DataHandleType) {
	t.Log("======================公钥加密和私钥解密======================")
	//
	data, err := goRsa.PubKeyEncrypt(input, dataHandleType)
	if err != nil {
		t.Log(err.Error())
		return
	}
	t.Log("加密结果：", data)
	//
	result, err := goRsa.PriKeyDecrypt([]byte(data), dataHandleType)
	if err != nil {
		t.Log(err.Error())
		return
	}
	t.Log("解密结果：", result)
}

//>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>gorsa end>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
