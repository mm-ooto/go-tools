package utils

import (
	"bytes"
	"crypto/md5"
	rand2 "crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/gob"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"math/rand"
	"net"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"git.900sui.cn/kc/kcgin/logs"
	"github.com/shopspring/decimal"
	"golang.org/x/crypto/pkcs12"
)

// HashMd5 md5加密
// @param  string str 待加密md5字符串
// @return string
func HashMd5(str string) string {
	md5Inst := md5.New()
	md5Inst.Write([]byte(str))
	result := md5Inst.Sum([]byte(""))
	return fmt.Sprintf("%x", result)
}

// HashSha1 sha1加密
// @param  string str 待加密sha1字符串
// @return string
func HashSha1(str string) string {
	sha1Inst := sha1.New()
	_, err := sha1Inst.Write([]byte(str))
	if err != nil {
		log.Fatal(err.Error())
	}
	result := sha1Inst.Sum([]byte(""))
	return fmt.Sprintf("%x", result)
}

// Base64Encode base64加密
// @param  string str 待加密字符串
// @return string
func Base64Encode(str string) string {
	//转换成byte类型
	strB := []byte(str)
	return base64.StdEncoding.EncodeToString(strB)
}

// Base64Decode base64解密
// @param  string str 待解密字符串
// @return string
func Base64Decode(str string) string {
	//转换成byte类型
	bytes, _ := base64.StdEncoding.DecodeString(str)
	return string(bytes[:])
}

// CheckPhone 验证手机号
// @param  string phone 待验证手机号
// @return bool
func CheckPhone(phone string) bool {
	regular := "^1\\d{10}$"
	reg := regexp.MustCompile(regular)
	return reg.MatchString(phone)
}

// CheckCall 验证固话
// @param  string tel 待验证固定电话
// @return bool
func CheckCall(tel string) bool {
	//分析参数
	if tel == "" {
		return false
	}
	pattern := "^[\\d]{3,4}\\-[\\d]{7,8}$"
	if bools, _ := regexp.MatchString(pattern, tel); bools {
		return true
	}
	return false
}

// CheckEmail 验证邮箱
// @param  string email 待验证邮箱
// @return bool
func CheckEmail(email string) bool {
	pattern := `^[0-9a-z][_.0-9a-z-]{0,31}@([0-9a-z][0-9a-z-]{0,30}[0-9a-z]\.){1,4}[a-z]{2,4}$`
	reg := regexp.MustCompile(pattern)
	return reg.MatchString(email)
}

// MarkPhone 马赛克中国大陆手机号
// @param  string     phone 待打马赛克手机号
// @param  ...string  re    马赛克默认标识 默认="*"
// @return string
func MarkPhone(phone string, re ...string) string {
	if len(phone) != 11 {
		return phone
	}
	var replaceMark string
	if len(re) == 0 {
		replaceMark = strings.Repeat("*", 5)
	} else {
		replaceMark = strings.Repeat(string(re[0]), 5)
	}
	replace := phone[3:8]
	return strings.Replace(phone, replace, replaceMark, 1)
}

// MarkNumberStr 马赛克字符串类型的数字
//
//	startIndex：开始下标；endIndex：结束下标；re：马赛克标识，默认*
func MarkNumberStr(numberStr string, startIndex, endIndex int, re ...string) string {
	if startIndex > endIndex {
		return numberStr
	}

	replaceMark := "*"
	if len(re) > 0 {
		replaceMark = re[0]
	}

	return strings.Replace(numberStr, numberStr[startIndex:endIndex], strings.Repeat(replaceMark, endIndex-startIndex), 1)
}

// GobEncode2Byte 使用gob编码将数据转化为byte切片
// @param  interface{} data gob数据
// @return mixted
func GobEncode2Byte(data interface{}) ([]byte, error) {
	buf := bytes.NewBuffer(nil)
	enc := gob.NewEncoder(buf)
	err := enc.Encode(data)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// GobDecodeByte gob编码的byte切片数据转化为其他数据
// @param  byte data 字节切片数组
// @return error
func GobDecodeByte(data []byte, to interface{}) error {
	buf := bytes.NewBuffer(data)
	dec := gob.NewDecoder(buf)
	return dec.Decode(to)
}

// StringsToJSON string字符串转json输出
// @param string str 待转字符串
// @return string
func StringsToJSON(str string) string {
	var jsons bytes.Buffer
	for _, r := range str {
		rint := int(r)
		if len(string(r)) == 4 {
			jsons.WriteRune(r)
		} else if rint < 128 {
			jsons.WriteRune(r)
		} else {
			jsons.WriteString("\\u")
			if rint < 0x100 {
				jsons.WriteString("00")
			} else if rint < 0x1000 {
				jsons.WriteString("0")
			}
			jsons.WriteString(strconv.FormatInt(int64(rint), 16))
		}
	}
	return jsons.String()
}

// Implode 把数组转换为字符串
// @param  string separator       转换分隔符
// @param  interface{}  interface 待转换数据
// @return string
func Implode(separator string, array interface{}) string {
	return strings.Replace(strings.Trim(fmt.Sprint(array), "[]"), " ", separator, -1)
}

var (
	randSrc                      = rand.NewSource(time.Now().UnixNano())
	BigSmallAlphabet             = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"           // 大小写字母
	NumberSmallAlphabet          = "0123456789abcdefghijklmnopqrstuvwxyz"                           // 数字+小写字母
	NumberBigSmallAlphabet       = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ" // 数字+大小写字母
	letterIdxBits          int64 = 6                                                                // 6 bits to represent a letter index
	letterIdxMask          int64 = 1<<letterIdxBits - 1                                             // All 1-bits, as many as letterIdxBits
	letterIdxMax                 = 63 / letterIdxBits                                               // # of letter indices fitting in 63 bits
)

// GenerateRandSeq 生成随机字符串（推荐使用这个方法）
//
//	n：随机字符串的长度
//	matchRule：生成规则（默认是 数字+大小写字母），可选项：functions.BigSmallAlphabet（大小写字母）
//	functions.NumberSmallAlphabet（数字+小写字母）、functions.NumberBigSmallAlphabet（数字+大小写字母）
func GenerateRandSeq(n int, matchRule ...string) string {
	b := make([]byte, n)

	ruleStr := NumberBigSmallAlphabet
	if len(matchRule) > 0 {
		ruleStr = matchRule[0]
	}

	// A randSrc.Int63() generates 63 random bits, enough for letterIdxMax characters!
	for i, cache, remain := n-1, randSrc.Int63(), letterIdxMax; i >= 0; {
		if remain == 0 {
			cache, remain = randSrc.Int63(), letterIdxMax
		}
		if idx := cache & letterIdxMask; idx < int64(len(ruleStr)) {
			b[i] = ruleStr[idx]
			i--
		}
		cache >>= letterIdxBits
		remain--
	}

	return string(b)
}

const (
	DATA_TIME_YMDHMS_FORMAT = "2006-01-02 15:04:05"
	DATA_TIME_YMDHM_FORMAT  = "2006-01-02 15:04"
	DATA_TIME_YMD_FORMAT    = "2006-01-02"
)

// StrtoTime 字符串转化为时间戳
// @param  string timeStr 日期字符串
// @return int64
func StrtoTime(timeStr string, timelayouts ...string) int64 {
	timeLayout := DATA_TIME_YMDHMS_FORMAT //转化所需模板
	if len(timelayouts) > 0 {
		timeLayout = timelayouts[0]
	}
	loc, _ := time.LoadLocation("Local")                         //重要：获取时区
	theTime, _ := time.ParseInLocation(timeLayout, timeStr, loc) //使用模板在对应时区转化为time.time类型
	return theTime.Unix()
}

// TimeToStr 时间戳转化为字符串
// @param  int64  timestamp  时间戳
// @return string
func TimeToStr(timestamp int64) string {
	tm := time.Unix(timestamp, 0)
	return tm.Format("2006/01/02 15:04:05")
}

// Timestamp2TimeStr 时间戳转为字符串
//
// timestampInter：时间戳，支持string、int64类型；layout：转换格式，默认 "2006-01-02 15:04"
func Timestamp2TimeStr(timestampInter interface{}, layout ...string) (dataTime string) {
	var timestamp int64
	switch timestampInter.(type) {
	case string:
		timestamp, _ = strconv.ParseInt(timestampInter.(string), 10, 64)
	case int64:
		timestamp = timestampInter.(int64)
	default:
		return ""
	}

	var format string
	if len(layout) == 0 {
		format = DATA_TIME_YMDHM_FORMAT
	} else {
		format = layout[0]
	}
	dataTime = time.Unix(timestamp, 0).Format(format)
	return
}

// Mb4Strlen 获取字符串长度
// @param  string str 待获取长度字符串
// @return int
func Mb4Strlen(str string) int {
	str = strings.TrimSpace(str)
	if len(str) == 0 {
		return 0
	}
	strRune := []rune(str)
	lens := len(strRune)
	return lens
}

// StuffStr 截取字符串
// @param string str   待截取的字符串
// @param int    index 截取开始位置
// @param int    lens  截取长度
func StuffStr(str string, index int, lens int) string {
	str = strings.TrimSpace(str)
	if len(str) == 0 {
		return str
	}
	strRune := []rune(str)
	if len(strRune) < lens {
		lens = len(strRune)
	}
	return string(strRune[index:lens])
}

// ArrayKeys map转Int数组
func ArrayKeys(maps map[int]interface{}) []int {
	//分析参数
	if len(maps) == 0 {
		return make([]int, 0)
	}
	var arr = make([]int, 0)
	for i, _ := range maps {
		arr = append(arr, i)
	}
	return arr
}

// ArrayValue2Array map数组转Int数组
func ArrayValue2Array(field string, maps []map[string]interface{}) []int {
	//分析参数
	if len(maps) == 0 {
		return make([]int, 0)
	}
	var arr = make([]int, 0)
	for _, m := range maps {
		v, ok := m[field]
		if ok {
			if vs, p := v.(string); p {
				n, _ := strconv.Atoi(vs)
				arr = append(arr, n)
			}
			if vs, p := v.(int); p {
				arr = append(arr, vs)
			}
		}
	}
	return arr
}

// ArrayRebuild map数组转map
func ArrayRebuild(field string, maps []map[string]interface{}) map[string]interface{} {
	//分析参数
	if len(maps) == 0 {
		return make(map[string]interface{}, 0)
	}
	var reMap = make(map[string]interface{})
	for _, m := range maps {
		v, ok := m[field]
		if ok {
			if vs, p := v.(int); p {
				reMap[strconv.Itoa(vs)] = m
			}
			if vs, p := v.(string); p {
				reMap[vs] = m
			}
			if vs, p := v.(float64); p {
				reMap[strconv.FormatFloat(vs, 'f', -1, 64)] = m
			}
			if vs, p := v.(float32); p {
				reMap[strconv.FormatFloat(float64(vs), 'f', -1, 64)] = m
			}
		}
	}
	return reMap
}

// SortsMap 数组map排序
func SortsMap(field string, maps []map[string]interface{}) []map[string]interface{} {
	var mapData = make(map[string]interface{})
	var keys = make([]string, 0)
	for _, v := range maps {
		vs := v[field]
		if vp, ok := vs.(float64); ok {
			vs = strconv.FormatFloat(vp, 'f', -1, 64)
		}
		if vp, ok := vs.(int); ok {
			vs = strconv.FormatInt(int64(vp), 10)
		}
		if vp, ok := vs.(string); ok {
			vs = vp
		}
		mapData[vs.(string)] = v
		keys = append(keys, vs.(string))
	}
	sort.Strings(keys)
	remapData := make([]map[string]interface{}, 0)
	for _, v := range keys {
		remapData = append(remapData, mapData[v].(map[string]interface{}))
	}
	return remapData
}

// InArray 判断search是否在数组array里面（array仅支持[]int和[]string）
func InArray(search interface{}, array interface{}) bool {
	if arr, ok := array.([]int); ok {
		for _, val := range arr {
			if val == search {
				return true
			}
		}
	}
	if arr, ok := array.([]string); ok {
		for _, val := range arr {
			if val == search {
				return true
			}
		}
	}
	return false
}

// ArrayUniqueInt 整型数组去重
func ArrayUniqueInt(arr []int) []int {
	if len(arr) == 0 {
		return arr
	}
	newArr := make([]int, 0)
	for i := 0; i < len(arr); i++ {
		repeat := false
		for j := i + 1; j < len(arr); j++ {
			if arr[i] == arr[j] {
				repeat = true
				break
			}
		}
		if arr[i] == 0 {
			continue
		}

		if !repeat {
			newArr = append(newArr, arr[i])
		}
	}
	return newArr
}

// ArrayUniqueString 整型数组去重
func ArrayUniqueString(arr []string) []string {
	if len(arr) == 0 {
		return arr
	}
	newArr := make([]string, 0)
	for i := 0; i < len(arr); i++ {
		repeat := false
		for j := i + 1; j < len(arr); j++ {
			if arr[i] == arr[j] {
				repeat = true
				break
			}
		}
		if arr[i] == "" {
			continue
		}

		if repeat == false {
			newArr = append(newArr, arr[i])
		}
	}
	return newArr
}

// ClientIP 尽最大努力实现获取客户端 IP。
// 解析 X-Real-IP 和 X-Forwarded-For 以便于反向代理（nginx 或 haproxy）可以正常工作。
func ClientIP(r *http.Request) string {
	xForwardedFor := r.Header.Get("X-Forwarded-For")
	ip := strings.TrimSpace(strings.Split(xForwardedFor, ",")[0])
	if ip != "" {
		return ip
	}

	ip = strings.TrimSpace(r.Header.Get("X-Real-Ip"))
	if ip != "" {
		return ip
	}

	if ip, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr)); err == nil {
		return ip
	}

	return ""
}

// GetPemPublic 公钥转换
func GetPemPublic(publicKey string) string {
	res := "-----BEGIN PUBLIC KEY-----\n"
	strlen := len(publicKey)
	for i := 0; i < strlen; i += 64 {
		if i+64 >= strlen {
			res += publicKey[i:] + "\n"
		} else {
			res += publicKey[i:i+64] + "\n"
		}
	}
	res += "-----END PUBLIC KEY-----"
	return res
}

// GetPemPrivate 私钥转换
func GetPemPrivate(privateKey string) string {
	res := "-----BEGIN RSA PRIVATE KEY-----\n"
	strlen := len(privateKey)
	for i := 0; i < strlen; i += 64 {
		if i+64 >= strlen {
			res += privateKey[i:] + "\n"
		} else {
			res += privateKey[i:i+64] + "\n"
		}
	}
	res += "-----END RSA PRIVATE KEY-----"
	return res
}

// FormatCertKey 格式化证书
func FormatCertKey(certKey string) string {
	var publicHeader = "-----BEGIN CERTIFICATE-----\n"
	var publicTail = "-----END CERTIFICATE-----\n"
	var temp string
	split(certKey, &temp)
	return publicHeader + temp + publicTail
}

func split(key string, temp *string) {
	if len(key) <= 64 {
		*temp = *temp + key + "\n"
	}
	for i := 0; i < len(key); i++ {
		if (i+1)%64 == 0 {
			*temp = *temp + key[:i+1] + "\n"
			key = key[i+1:]
			split(key, temp)
			break
		}
	}
}

// DetectBinary 判断给定的文件是否是二进制
func DetectBinary(path string) bool {
	file, err := os.Open(path)
	if err != nil {
		return false
	}
	defer file.Close()

	// 定义缓冲区大小
	bufferSize := 1024
	buf := make([]byte, bufferSize)

	// 读取文件前 1024 字节
	n, err := file.Read(buf)
	if err != nil && err != io.EOF {
		return false
	}

	// 如果读取不到任何数据，则认为不是二进制文件
	if n == 0 {
		return false
	}

	// 定义可打印字符范围
	isPrintable := func(b byte) bool {
		return b >= 0x20 && b <= 0x7E || // ASCII 可打印字符
			b == 0x09 || b == 0x0A || b == 0x0D || // 换行符、制表符等
			b >= 0xC2 && b <= 0xF4 // UTF-8 多字节字符开头
	}

	// 遍历缓冲区，检查是否存在非打印字符
	for i := 0; i < n; i++ {
		if !isPrintable(buf[i]) {
			// 如果发现非打印字符，直接返回 true
			return true
		}
	}

	// 如果所有字符都在可打印范围内，则认为不是二进制文件
	return false
}

// StrExplode2IntArr 字符串切割成int型数组
func StrExplode2IntArr(s string, step string) []int {
	strs := strings.Split(s, ",")
	var outData []int
	for _, v := range strs {
		if len(v) == 0 {
			continue
		}
		intv, _ := strconv.Atoi(v)
		outData = append(outData, intv)
	}
	return outData
}

// NumberConvertUpper 数字转大写
//
// amount：金额；isRound：是否四舍五入
// 例子：2784.64 -> 贰仟柒佰捌拾肆圆陆角肆分
func NumberConvertUpper(amount float64, isRound bool) string {
	// 定义数字和单位映射
	var (
		NumberUpper = []string{"零", "壹", "贰", "叁", "肆", "伍", "陆", "柒", "捌", "玖"}
		Unit        = []string{"分", "角", "圆", "拾", "佰", "仟", "万", "拾", "佰", "仟", "亿", "拾", "佰", "仟"}
	)

	// 特殊情况处理
	if amount == 0 {
		return "零"
	}

	// 处理负数
	isNegative := false
	if amount < 0 {
		isNegative = true
		amount = math.Abs(amount)
	}

	// 四舍五入处理
	round := 1
	if isRound {
		round = 2
	}
	digitStr := strconv.FormatFloat(amount, 'f', round+1, 64)

	// 构建结果字符串
	var builder strings.Builder
	unitLen := len(digitStr) - round
	zeroFlag := false // 标记连续的零
	for _, ch := range digitStr {
		if ch == '.' {
			unitLen = 2 // 小数部分单位从角开始
			continue
		}

		// 转换数字
		num, _ := strconv.Atoi(string(ch))
		if num != 0 {
			if zeroFlag {
				builder.WriteString("零")
				zeroFlag = false
			}
			builder.WriteString(NumberUpper[num])
			if unitLen > 0 {
				builder.WriteString(Unit[unitLen-1])
			}
		} else {
			zeroFlag = true
		}
		unitLen--
	}

	// 后处理：去除冗余字符
	result := builder.String()
	result = optimizeResult(result)

	// 添加负号
	if isNegative {
		result = "负" + result
	}

	return result
}

// optimizeResult 对结果进行后处理，去除冗余字符
func optimizeResult(input string) string {
	// 定义替换规则
	replacements := map[string]string{
		"零拾": "零", "零佰": "零", "零仟": "零",
		"零零零": "零", "零零": "零",
		"零角零分": "整", "零分": "整", "零角": "零",
		"零亿零万零元": "亿元", "亿零万零元": "亿元",
		"零亿零万": "亿", "零万零元": "万元", "万零元": "万元",
		"零亿": "亿", "零万": "万", "拾零圆": "拾元", "零圆": "元",
	}

	// 执行替换
	for old, new2 := range replacements {
		input = strings.ReplaceAll(input, old, new2)
	}

	// 去除末尾多余的零
	if strings.HasSuffix(input, "零") {
		input = input[:len(input)-1]
	}

	return input
}

// PointConvertUnit 将分转换成元
//
//	precision：保留几位小数，默认2位小数
func PointConvertUnit(amount interface{}, precision ...int32) float64 {

	var pre int32 = 2
	if len(precision) > 0 {
		pre = precision[0]
	}

	var point int64
	switch amount.(type) {
	case int64:
		point = amount.(int64)
	case string:
		point, _ = strconv.ParseInt(amount.(string), 10, 64)
	}
	unit, _ := decimal.NewFromInt(point).Div(decimal.NewFromInt(int64(100))).Truncate(pre).Float64()
	return unit
}

// UnitConvertPoint 将元转换成分
func UnitConvertPoint(amount interface{}) int64 {
	var point int64
	unit := decimal.NewFromInt(int64(100))

	// 提前进行类型断言并赋值
	switch v := amount.(type) {
	case float64:
		point = decimal.NewFromFloat(v).Mul(unit).IntPart()
	case string:
		amountStr, err := decimal.NewFromString(v)
		if err != nil {
			return 0 // 或者根据需求处理错误
		}
		point = amountStr.Mul(unit).IntPart()
	default:
		return 0
	}

	return point
}

// ParseAndValidateSignature 从 JSON 字符串中解析数据、提取并验证签名字段
//
// 参数：
//
//	resBodyJsonStr - 待解析的 JSON 字符串（含签名字段）
//	signatureFieldName - 签名字段，默认是signature，如果不是可以指定
//
// 返回值：
//
//	data       - 移除签名后的原始数据集合
//	signature  - 提取的签名字符串
//	err        - 错误信息（包含 JSON 解析失败、签名缺失、类型错误、内容为空等情况）
func ParseAndValidateSignature(resBodyJsonStr string, signatureFieldName ...string) (data map[string]interface{}, signature string, err error) {
	// 反序列化 JSON
	data = make(map[string]interface{})
	if err = json.Unmarshal([]byte(resBodyJsonStr), &data); err != nil {
		err = fmt.Errorf("JSON解析失败: %v", err)
		return
	}

	signatureField := "signature"
	if len(signatureFieldName) > 0 {
		signatureField = signatureFieldName[0]
	}
	// 检查签名是否存在
	if _, ok := data[signatureField]; !ok {
		err = errors.New("缺少签名字段")
		return
	}

	// 校验签名类型和内容
	signature, ok := data[signatureField].(string)
	if !ok {
		err = errors.New("签名类型错误")
		return
	}
	if signature == "" {
		err = errors.New("签名不能为空")
		return
	}

	// 删除签名字段
	delete(data, signatureField)
	return
}

// GenerateSignatureString 生成待签名字符串
// 处理规则:
//   - 自动过滤签名字段"signature"（如果需要额外过滤的字段则可以通过字段filterFields来指定）
//   - 如果key是businessData（如果字段名不是businessData也可以通过businessDataFieldName字段来指定）的话，则会保留"businessData"字段的原始JSON结构（不进行内部字段排序）
//   - 其他字段按ASCII码升序排列并序列化
//   - 自动过滤空值(null)、空字符串、空数组和空对象
//
// 参数:
//   - data: interface{} 待处理的数据对象，支持结构体或map类型
//   - filterFields - []string{} 签名过程中需要过滤掉的字段
//   - businessDataFieldName string    - 业务数据字段名
//
// 返回值:
//   - signatureStr string 格式化后的待签名字符串
func GenerateSignatureString(data interface{}, filterFields []string, businessDataFieldName ...string) string {
	byteB, _ := json.Marshal(data)
	var rawReqData map[string]json.RawMessage
	_ = json.Unmarshal(byteB, &rawReqData)

	delete(rawReqData, "signature")
	for _, field := range filterFields {
		delete(rawReqData, field)
	}

	businessField := "businessData"
	if len(businessDataFieldName) > 0 {
		businessField = businessDataFieldName[0]
	}

	reqData := make(map[string]interface{})
	for key, rawValue := range rawReqData {
		if key == businessField {
			// 保留原始的JSON字符串，避免二次序列化
			reqData[key] = string(rawValue)
		} else {
			var value interface{}
			_ = json.Unmarshal(rawValue, &value)
			reqData[key] = value
		}
	}

	var keys []string
	for key := range reqData {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	var str strings.Builder
	for _, key := range keys {
		keyValue := reqData[key]
		var valueStr string
		switch v := keyValue.(type) {
		case string:
			valueStr = v
			// 可根据需要处理其他类型，如数值、布尔值等
		}
		if valueStr != "" && valueStr != "[]" && valueStr != "null" && valueStr != "{}" {
			str.WriteString(key)
			str.WriteString("=")
			str.WriteString(valueStr)
			str.WriteString("&")
		}
	}

	result := str.String()
	if len(result) > 0 {
		result = result[:len(result)-1] // 去除末尾的"&"
	}
	logs.Info("待签名字符串：", result)
	return result
}

// GenerateSignatureString2 生成待签名字符串2
//
// 处理规则:
//   - 自动过滤签名字段"signature"（如果需要额外过滤的字段则可以通过字段filterFields来指定）
//   - 如果key是businessData（如果字段名不是businessData也可以通过businessDataFieldName字段来指定）的话，则不会保留"businessData"字段的原始JSON结构（会对其内部字段按ASCII码升序排列）
//   - 其他字段按ASCII码升序排列并序列化
//   - 自动过滤空值(null)、空字符串、空数组和空对象
//
// 参数:
//   - data: interface{} 待处理的数据对象，支持结构体或map类型
//   - filterFields - []string{} 签名过程中需要过滤掉的字段
//   - businessDataFieldName  string   - 业务数据字段名
//
// 返回值:
//   - signatureStr string 格式化后的待签名字符串
//   - originSignature string data内部原始的签名
func GenerateSignatureString2(data interface{}, filterFields []string, businessDataFieldName ...string) string {

	var rawReqData map[string]interface{}
	byteB, _ := json.Marshal(data)
	_ = json.Unmarshal(byteB, &rawReqData)

	delete(rawReqData, "signature")
	for _, field := range filterFields {
		delete(rawReqData, field)
	}

	businessField := "businessData"
	if len(businessDataFieldName) > 0 {
		businessField = businessDataFieldName[0]
	}

	var keys []string
	for key, _ := range rawReqData {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	var str strings.Builder

	for _, key := range keys {
		keyValue := rawReqData[key]
		if key == businessField {
			// TODO 这里会对businessData对象内部做一个排序
			keyValueByte, _ := json.Marshal(keyValue)
			keyValue = string(keyValueByte)
		}
		var valueStr string
		switch value := keyValue.(type) {
		case string:
			valueStr = value
		}
		if valueStr != "" && valueStr != "[]" && valueStr != "null" && valueStr != "{}" {
			str.WriteString(key)
			str.WriteString("=")
			str.WriteString(valueStr)
			str.WriteString("&")
		}
	}

	result := str.String()
	if len(result) > 0 {
		result = result[:len(result)-1] // 去除末尾的"&"
	}

	logs.Info("待签名字符串：", result)

	return result
}

// GetPrivateKeyFromPfxFile 从pfx证书文件中解析出私钥
//
//	privateKeyFile：私钥文件路径；privatePassword：密钥
func GetPrivateKeyFromPfxFile(privateKeyFile, privatePassword string) (*rsa.PrivateKey, error) {

	byteB, err := os.ReadFile(privateKeyFile)
	if err != nil {
		return nil, fmt.Errorf("读取私钥证书失败 file err:%s", err.Error())
	}

	priKey, _, err := pkcs12.Decode(byteB, privatePassword)
	if err != nil {
		return nil, fmt.Errorf("解密失败")
	}

	privateKey := priKey.(*rsa.PrivateKey)

	return privateKey, nil
}

// LoadPrivateKey 加载私钥
//
//	privateKeyFile：私钥文件路径；
func LoadPrivateKey(privateKeyFile string) (privateKey *rsa.PrivateKey, err error) {
	privateKeyBytes, err := os.ReadFile(privateKeyFile)
	if err != nil {
		return nil, fmt.Errorf("读取私钥失败 file err:%s", err.Error())
	}
	block, _ := pem.Decode(privateKeyBytes)
	if block == nil {
		return nil, fmt.Errorf("解码私钥失败")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("解析私钥失败 err:%s", err.Error())
	}
	return key.(*rsa.PrivateKey), nil
}

// GetPublicKeyFromCert 从证书文件中中获取公钥
//
//	certFilePath：公钥证书文件路径
func GetPublicKeyFromCert(certFilePath string) (*rsa.PublicKey, error) {

	byteB, err := os.ReadFile(certFilePath)
	if err != nil {
		return nil, err
	}

	// 如果.cer内容是二进制的，需要转换一下
	if DetectBinary(certFilePath) {
		temp := FormatCertKey(base64.StdEncoding.EncodeToString(byteB))
		byteB = []byte(temp)
	}

	// 解码
	block, _ := pem.Decode(byteB)

	// 证书解析
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}

	//// 提取公钥
	//publicKeyDer, _ := x509.MarshalPKIXPublicKey(cert.PublicKey)
	//publicKeyBlock := pem.Block{
	//	Type:  "PUBLIC KEY",
	//	Bytes: publicKeyDer,
	//}
	//publicKeyPem := string(pem.EncodeToMemory(&publicKeyBlock))
	//fmt.Println(publicKeyPem)

	publicKey := cert.PublicKey.(*rsa.PublicKey)
	return publicKey, nil
}

// GetPemBlockFromPfxFile 将pfx证书转换为PEM块
//
//	privateKeyFile：私钥文件路径；privatePassword：密钥
func GetPemBlockFromPfxFile(privateKeyFile, privatePassword string) ([]*pem.Block, error) {

	byteB, err := os.ReadFile(privateKeyFile)
	if err != nil {
		return nil, fmt.Errorf("读取私钥证书失败 file err:%s", err.Error())
	}
	// 因为pfx证书公钥和密钥是成对的，所以要先转成pem.Block
	blocks, err := pkcs12.ToPEM(byteB, privatePassword)
	if err != nil {
		return nil, fmt.Errorf("解码私钥失败  err:%s", err.Error())
	}
	if len(blocks) != 2 {
		return nil, fmt.Errorf("解码私钥失败")
	}
	return blocks, nil
}

// GenerateRSAKey 生成RSA密钥对，公钥和私钥保存为文件
//
//	privateFile 私钥文件；publicFile 公钥文件；bits 证书大小
func GenerateRSAKey(privateFile, publicFile string, bits int) error {
	//GenerateKey函数使用随机数据生成器random生成一对具有指定字位数的RSA密钥
	//Reader是一个全局、共享的密码用强随机数生成器
	privateKey, err := rsa.GenerateKey(rand2.Reader, bits)
	if err != nil {
		return err
	}

	// 通过x509标准将得到的ras私钥序列化为 ASN.1 的 DER 编码字符串
	x509PrivateKey := x509.MarshalPKCS1PrivateKey(privateKey)

	//新建私钥文件
	privateKeyFile, err := os.Create(privateFile)
	if err != nil {
		return err
	}
	defer privateKeyFile.Close()

	// 构建一个pem.Block结构体对象
	// 将数据保存到私钥文件
	err = pem.Encode(privateKeyFile, &pem.Block{
		Type:    "RSA Private Key",
		Headers: map[string]string{},
		Bytes:   x509PrivateKey,
	})
	if err != nil {
		return err
	}

	// X509对公钥编码
	X509PublicKey, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return err
	}

	// 新建公钥文件
	publicKeyFile, err := os.Create(publicFile)
	if err != nil {
		return err
	}
	defer publicKeyFile.Close()

	// 构建一个pem.Block结构体对象
	// 将数据保存到公钥文件
	err = pem.Encode(publicKeyFile, &pem.Block{
		Type:    "RSA Public Key",
		Headers: map[string]string{},
		Bytes:   X509PublicKey,
	})
	if err != nil {
		return err
	}

	return nil
}

// GenerateBatchUpdateSQL 生成批量更新 SQL
// 参数:
// - tableName: 表名
// - data: 数据集合，必须包含 fieldKey 字段
// - fieldKey: 主键字段名（如 "id"）
// - whereCondition: 可选附加条件（如 "status = 'active'")
// 返回生成的 SQL 和可能的错误
func GenerateBatchUpdateSQL(tableName string, data []map[string]interface{}, fieldKey string, whereCondition ...string) (string, error) {
	if len(data) == 0 {
		return "", fmt.Errorf("data cannot be empty")
	}

	// 1. 提取需要更新的字段（排除主键）
	fields := make([]string, 0)
	for key := range data[0] {
		if key != fieldKey {
			fields = append(fields, key)
		}
	}

	// 2. 收集主键值并去重
	idMap := make(map[interface{}]struct{})
	for _, record := range data {
		if idVal, ok := record[fieldKey]; ok {
			idMap[idVal] = struct{}{}
		} else {
			return "", fmt.Errorf("fieldKey '%s' not found in record", fieldKey)
		}
	}

	// 3. 构建 CASE WHEN 语句
	caseStatements := make([]string, len(fields))
	for i, field := range fields {
		caseBuilder := new(strings.Builder)
		_, _ = fmt.Fprintf(caseBuilder, "`%s` = CASE `%s`", field, fieldKey)

		for _, record := range data {
			idVal := record[fieldKey]
			fieldVal := record[field]
			_, _ = fmt.Fprintf(caseBuilder, " WHEN %s THEN %s",
				formatSQLValue(idVal),
				formatSQLValue(fieldVal),
			)
		}
		caseBuilder.WriteString(" END")
		caseStatements[i] = caseBuilder.String()
	}

	// 4. 构建 WHERE 子句
	var whereClause strings.Builder
	// 主键 IN 条件
	inClause := make([]string, 0, len(idMap))
	for id := range idMap {
		inClause = append(inClause, formatSQLValue(id))
	}
	_, _ = fmt.Fprintf(&whereClause, "`%s` IN (%s)", fieldKey, strings.Join(inClause, ", "))

	// 附加条件（支持多个条件）
	if len(whereCondition) > 0 {
		for _, cond := range whereCondition {
			if cond != "" {
				_, _ = fmt.Fprintf(&whereClause, " AND (%s)", cond)
			}
		}
	}

	// 5. 最终 SQL 拼接
	sql := fmt.Sprintf(
		"UPDATE `%s`\nSET\n    %s\nWHERE %s;",
		tableName,
		strings.Join(caseStatements, ",\n    "),
		whereClause.String(),
	)
	logs.Info(sql)

	return sql, nil
}

// formatSQLValue 安全格式化值（防止 SQL 注入）
func formatSQLValue(value interface{}) string {
	switch v := value.(type) {
	case string:
		return "'" + strings.ReplaceAll(v, "'", "''") + "'"
	case time.Time:
		return "'" + v.Format("2006-01-02 15:04:05") + "'"
	case nil:
		return "NULL"
	default:
		return fmt.Sprintf("%v", v)
	}
}
