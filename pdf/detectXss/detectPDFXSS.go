package detectXss

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/unidoc/unipdf/v3/core"
	"github.com/unidoc/unipdf/v3/model"
)

// ConfigManager 配置管理器，用于管理PDF扫描的各项参数
type ConfigManager struct {
	maxParallelScans int           // 最大并行扫描数
	contentScanLimit int64         // 内容流扫描限制
	timeoutDuration  time.Duration // 超时时间
	bufferSize       int           // 缓冲区大小
	maxObjectSize    int           // 对象大小限制
	maxRecursion     int           // 限制递归深度
}

var (
	configManager = &ConfigManager{
		maxParallelScans: 2,                 // 对于大文件，使用2个并行扫描
		contentScanLimit: 100 * 1024 * 1024, // 100MB 内容流扫描限制
		timeoutDuration:  10 * time.Minute,  // 10分钟超时时间
		bufferSize:       524288,            // 512KB 缓冲区大小
		maxObjectSize:    10 * 1024 * 1024,  // 10MB 对象大小限制
		maxRecursion:     30,                // 减少递归深度以提高稳定性
	}
)

// SetMaxParallelScans 设置最大并行扫描数
// 参数:
//   - n: 并行扫描数，必须大于0
func SetMaxParallelScans(n int) {
	if n > 0 {
		configManager.maxParallelScans = n
	}
}

// SetContentScanLimit 设置内容流扫描限制
// 参数:
//   - limit: 内容流大小限制，必须大于0
func SetContentScanLimit(limit int64) {
	if limit > 0 {
		configManager.contentScanLimit = limit
	}
}

// SetTimeoutDuration 设置超时时间
// 参数:
//   - duration: 超时时间，必须大于0
func SetTimeoutDuration(duration time.Duration) {
	if duration > 0 {
		configManager.timeoutDuration = duration
	}
}

// SetBufferSize 设置缓冲区大小
// 参数:
//   - size: 缓冲区大小，必须大于0
func SetBufferSize(size int) {
	if size > 0 {
		configManager.bufferSize = size
	}
}

// SetMaxObjectSize 设置对象大小限制
// 参数:
//   - size: 对象大小限制，必须大于0
func SetMaxObjectSize(size int) {
	if size > 0 {
		configManager.maxObjectSize = size
	}
}

// 检测配置
const (
	jsDetectionRegex = `(?i)(?:^|\s)(?:/JS\b|/JavaScript\b|/Type\s*/Action.*/S\s*/JavaScript)(?:$|\s)`
	riskActions      = "/JavaScript,/JS,/URI,/Launch,/SubmitForm"
)

var (
	jsPattern = regexp.MustCompile(jsDetectionRegex)
	riskKeys  = strings.Split(riskActions, ",")
)

// DetectPDFXSS 统一的PDF XSS检测入口
// 参数:
//   - input: 输入参数，可以是文件路径(string)或文件字节数组([]byte)
//
// 返回:
//   - error: 如果检测到XSS风险返回错误信息，否则返回nil
func DetectPDFXSS(input interface{}) error {
	var found bool
	var err error

	switch v := input.(type) {
	case string:
		// 文件路径检测
		found, err = detectPDFXSS(v)
	case []byte:
		// 字节数组检测
		found, err = detectPDFXSSFromFileByte(v)
	default:
		return fmt.Errorf("不支持的输入类型: %T", input)
	}

	if err != nil {
		return fmt.Errorf("PDF检测失败: %v", err)
	}

	if found {
		return fmt.Errorf("检测到PDF文件包含XSS漏洞风险，可能存在JavaScript注入攻击")
	}

	return nil
}

// checkRiskKeyValue 检查PDF对象是否包含风险键值
// 参数:
//   - obj: 要检查的PDF对象
//
// 返回:
//   - bool: 如果对象包含风险键值返回true，否则返回false
func checkRiskKeyValue(obj core.PdfObject) bool {
	switch v := core.TraceToDirectObject(obj).(type) {
	case *core.PdfObjectString:
		// 检查字符串是否包含完整的JS标识
		str := v.Str()
		if !strings.Contains(str, "JavaScript") && !strings.Contains(str, "/JS") {
			return false
		}
		return jsPattern.MatchString(str)
	case *core.PdfObjectDictionary:
		// 只检查明确标记为JavaScript的Action
		if s := v.Get("S"); s != nil {
			if name, ok := core.TraceToDirectObject(s).(*core.PdfObjectName); ok {
				nameStr := name.String()
				return strings.EqualFold(nameStr, "JavaScript") || strings.EqualFold(nameStr, "JS")
			}
		}
	}
	return false
}

// detectPDFXSS 主检测入口，检测PDF文件是否包含XSS风险
// 参数:
//   - filePath: PDF文件路径
//
// 返回:
//   - bool: 如果检测到XSS风险返回true，否则返回false
//   - error: 如果检测过程中发生错误返回错误信息
func detectPDFXSS(filePath string) (bool, error) {
	firstTime := time.Now().Local()
	defer func() {
		log.Printf("detectPDFXSS Scanning time %.2fs ", time.Now().Local().Sub(firstTime).Seconds())
	}()

	ctx, cancel := context.WithTimeout(context.Background(), configManager.timeoutDuration)
	defer cancel()

	file, err := os.Open(filePath)
	if err != nil {
		return false, fmt.Errorf("文件打开失败: %v", err)
	}
	defer file.Close()

	// 快速检测层
	if found, err := fastDetection(file); found || err != nil {
		return found, err
	}

	// 深度检测层
	return deepDetection(ctx, file)
}

// fastDetection 快速检测PDF文件是否包含XSS风险
// 参数:
//   - file: 已打开的PDF文件
//
// 返回:
//   - bool: 如果检测到XSS风险返回true，否则返回false
//   - error: 如果检测过程中发生错误返回错误信息
func fastDetection(file *os.File) (bool, error) {
	_, _ = file.Seek(0, 0)

	// 使用文件直接创建PDF读取器
	pdfReader, err := model.NewPdfReader(file)
	if err != nil {
		return false, fmt.Errorf("创建PDF读取器失败: %v", err)
	}

	// 获取Catalog字典
	catalogDict, err := getCatalogDict(pdfReader)
	if err != nil {
		return false, err
	}

	// 检查Catalog中的关键区域
	if checkCatalogObjects(catalogDict) {
		return true, nil
	}

	// 2. 快速页面扫描
	return quickPageCheck(pdfReader, 3)
}

// deepDetection 深度检测PDF文件是否包含XSS风险，带超时控制
// 参数:
//   - ctx: 上下文，用于控制超时
//   - file: 已打开的PDF文件
//
// 返回:
//   - bool: 如果检测到XSS风险返回true，否则返回false
//   - error: 如果检测过程中发生错误返回错误信息
func deepDetection(ctx context.Context, file *os.File) (bool, error) {
	result := make(chan bool, 1)
	errChan := make(chan error, 1)

	go func() {
		// 使用文件直接创建PDF读取器
		reader, err := model.NewPdfReader(file)
		if err != nil {
			errChan <- fmt.Errorf("创建PDF读取器失败: %v", err)
			return
		}

		// 全对象扫描
		result <- fullObjectScan(reader)
	}()

	select {
	case <-ctx.Done():
		return false, fmt.Errorf("检测超时")
	case err := <-errChan:
		return false, err
	case found := <-result:
		return found, nil
	}
}

// checkCatalogObjects 检查Catalog字典中的关键对象是否包含XSS风险
// 参数:
//   - catalogDict: PDF的Catalog字典
//
// 返回:
//   - bool: 如果检测到XSS风险返回true，否则返回false
func checkCatalogObjects(catalogDict *core.PdfObjectDictionary) bool {
	visited := make(map[core.PdfObject]struct{})
	var mu sync.Mutex

	// 检查OpenAction
	if analyzeObject(catalogDict.Get("OpenAction"), visited, &mu) {
		return true
	}

	// 检查Catalog附加动作
	if analyzeObject(catalogDict.Get("AA"), visited, &mu) {
		return true
	}

	// 检查AcroForm
	if analyzeObject(catalogDict.Get("AcroForm"), visited, &mu) {
		return true
	}

	// 检查JavaScript名称树
	if jsNameTree := getJavaScriptNameTree(catalogDict); jsNameTree != nil {
		return analyzeObject(jsNameTree, visited, &mu)
	}

	return false
}

// getJavaScriptNameTree 获取JavaScript名称树
// 参数:
//   - catalogDict: PDF的Catalog字典
//
// 返回:
//   - core.PdfObject: JavaScript名称树对象，如果不存在返回nil
func getJavaScriptNameTree(catalogDict *core.PdfObjectDictionary) core.PdfObject {
	namesDict, ok := core.TraceToDirectObject(catalogDict.Get("Names")).(*core.PdfObjectDictionary)
	if !ok {
		return nil
	}
	return core.TraceToDirectObject(namesDict.Get("JavaScript"))
}

// getCatalogDict 获取PDF的Catalog字典
// 参数:
//   - reader: PDF读取器
//
// 返回:
//   - *core.PdfObjectDictionary: Catalog字典
//   - error: 如果获取失败返回错误信息
func getCatalogDict(reader *model.PdfReader) (*core.PdfObjectDictionary, error) {
	trailerDict, err := reader.GetTrailer()
	if err != nil {
		return nil, fmt.Errorf("invalid trailer: %v", err)
	}

	rootObj := core.TraceToDirectObject(trailerDict.Get("Root"))
	catalogDict, ok := rootObj.(*core.PdfObjectDictionary)
	if !ok {
		return nil, fmt.Errorf("invalid catalog type: %T", rootObj)
	}
	return catalogDict, nil
}

// quickPageCheck 快速检查PDF页面是否包含XSS风险
// 参数:
//   - reader: PDF读取器
//   - maxPages: 最大检查页面数
//
// 返回:
//   - bool: 如果检测到XSS风险返回true，否则返回false
//   - error: 如果检测过程中发生错误返回错误信息
func quickPageCheck(reader *model.PdfReader, maxPages int) (bool, error) {
	numPages, err := reader.GetNumPages()
	if err != nil {
		return false, fmt.Errorf("failed to get page count: %v", err)
	}

	if numPages > maxPages {
		numPages = maxPages
	}

	for i := 1; i <= numPages; i++ {
		page, err := reader.GetPage(i)
		if err != nil {
			continue
		}

		// 检查页面内容流
		if checkPageStreams(page) {
			return true, nil
		}

		// 检查注释
		if checkPageAnnotations(page) {
			return true, nil
		}
	}

	return false, nil
}

// checkPageStreams 检查页面内容流是否包含XSS风险
// 参数:
//   - page: PDF页面对象
//
// 返回:
//   - bool: 如果检测到XSS风险返回true，否则返回false
func checkPageStreams(page *model.PdfPage) bool {
	content, err := page.GetAllContentStreams()
	if err != nil || len(content) > int(configManager.contentScanLimit) {
		return false
	}

	if jsPattern.MatchString(content) {
		return true
	}
	return false
}

// checkPageAnnotations 检查页面注释是否包含XSS风险
// 参数:
//   - page: PDF页面对象
//
// 返回:
//   - bool: 如果检测到XSS风险返回true，否则返回false
func checkPageAnnotations(page *model.PdfPage) bool {
	annots, ok := core.GetArray(page.GetPageDict().Get("Annots"))
	if !ok {
		return false
	}

	visited := make(map[core.PdfObject]struct{})
	var mu sync.Mutex

	for _, annot := range annots.Elements() {
		if dict, ok := core.GetDict(annot); ok {
			if analyzeObject(dict, visited, &mu) {
				return true
			}
		}
	}
	return false
}

// fullObjectScan 全对象扫描，检查PDF中所有对象是否包含XSS风险
// 参数:
//   - reader: PDF读取器
//
// 返回:
//   - bool: 如果检测到XSS风险返回true，否则返回false
func fullObjectScan(reader *model.PdfReader) bool {
	objNums := reader.GetObjectNums()
	visited := make(map[core.PdfObject]struct{})
	var mu sync.Mutex

	for _, num := range objNums {
		// 添加错误处理
		obj, err := reader.GetIndirectObjectByNumber(num)
		if err != nil {
			log.Printf("Error getting object %d: %v", num, err)
			continue
		}

		// 检查对象大小
		if objSize := estimateObjectSize(obj); objSize > configManager.maxObjectSize {
			log.Printf("Object %d too large: %d bytes", num, objSize)
			continue
		}

		// 安全地分析对象
		if safeAnalyzeObject(obj, visited, &mu) {
			return true
		}
	}

	return false
}

// estimateObjectSize 估算PDF对象的大小
// 参数:
//   - obj: PDF对象
//
// 返回:
//   - int: 对象的大小（字节数）
func estimateObjectSize(obj core.PdfObject) int {
	switch t := obj.(type) {
	case *core.PdfObjectDictionary:
		size := 0
		for _, key := range t.Keys() {
			size += len(key.String())
			if val := t.Get(key); val != nil {
				size += estimateObjectSize(val)
			}
		}
		return size
	case *core.PdfObjectArray:
		size := 0
		for _, elem := range t.Elements() {
			size += estimateObjectSize(elem)
		}
		return size
	case *core.PdfObjectString:
		return len(t.Str())
	case *core.PdfObjectStream:
		return len(t.Stream)
	default:
		return 0
	}
}

// safeAnalyzeObject 安全地分析PDF对象，包含panic恢复
// 参数:
//   - obj: 要分析的PDF对象
//   - visited: 已访问对象记录
//   - mu: 互斥锁
//
// 返回:
//   - bool: 如果检测到XSS风险返回true，否则返回false
func safeAnalyzeObject(obj core.PdfObject, visited map[core.PdfObject]struct{}, mu *sync.Mutex) bool {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("Recovered from panic in analyzeObject: %v", r)
		}
	}()
	return analyzeObject(obj, visited, mu)
}

// analyzeObject 分析PDF对象是否包含XSS风险
// 参数:
//   - obj: 要分析的PDF对象
//   - visited: 已访问对象记录
//   - mu: 互斥锁
//
// 返回:
//   - bool: 如果检测到XSS风险返回true，否则返回false
func analyzeObject(obj core.PdfObject, visited map[core.PdfObject]struct{}, mu *sync.Mutex) bool {
	return recursiveCheck(obj, visited, mu, 0)
}

// recursiveCheck 递归检查PDF对象是否包含XSS风险
// 参数:
//   - obj: 要检查的PDF对象
//   - visited: 已访问对象记录
//   - mu: 互斥锁
//   - depth: 当前递归深度
//
// 返回:
//   - bool: 如果检测到XSS风险返回true，否则返回false
func recursiveCheck(obj core.PdfObject, visited map[core.PdfObject]struct{}, mu *sync.Mutex, depth int) bool {
	if obj == nil {
		return false
	}

	// 限制递归深度
	if depth > configManager.maxRecursion {
		return false
	}

	mu.Lock()
	if _, exists := visited[obj]; exists {
		mu.Unlock()
		return false
	}
	visited[obj] = struct{}{}
	mu.Unlock()

	switch t := core.TraceToDirectObject(obj).(type) {
	case *core.PdfObjectDictionary:
		// 检查JS相关键值
		for _, key := range riskKeys {
			if val := t.Get(*core.MakeName(key)); val != nil {
				if checkRiskKeyValue(val) {
					return true
				}
			}
		}

		// 递归检查字典值
		for _, key := range t.Keys() {
			if recursiveCheck(t.Get(key), visited, mu, depth+1) {
				return true
			}
		}
	case *core.PdfObjectArray:
		// 限制数组大小
		if t.Len() > 1000 {
			return false
		}
		for _, elem := range t.Elements() {
			if recursiveCheck(elem, visited, mu, depth+1) {
				return true
			}
		}
	case *core.PdfObjectString:
		// 更严格的字符串检查
		str := t.Str()
		if !strings.Contains(str, "JavaScript") && !strings.Contains(str, "/JS") {
			return false
		}
		return jsPattern.MatchString(str)
	case *core.PdfObjectStream:
		// 仅检查表单类流对象
		if subtype, ok := t.PdfObjectDictionary.Get("Subtype").(*core.PdfObjectName); ok && *subtype == "Form" {
			decoded, err := core.DecodeStream(t)
			if err != nil {
				log.Printf("Error decoding stream: %v", err)
				return false
			}
			if jsPattern.Match(decoded) {
				return true
			}
		}
	case *core.PdfObjectName:
		// 更精确的名称检查
		name := strings.ToLower(t.String())
		return name == "javascript" || name == "js"
	}

	return false
}

// checkCriticalCatalog 检查关键目录是否包含XSS风险
// 参数:
//   - reader: PDF读取器
//
// 返回:
//   - bool: 如果检测到XSS风险返回true，否则返回false
func checkCriticalCatalog(reader *model.PdfReader) bool {
	trailerDict, err := reader.GetTrailer()
	if err != nil {
		return false
	}

	if trailerDict == nil {
		return false
	}

	// 通过Root字典访问Catalog
	rootDict, ok := core.GetDict(trailerDict.Get("Root"))
	if !ok {
		return false
	}

	visited := make(map[core.PdfObject]struct{})
	var mu sync.Mutex

	// 检测OpenAction风险
	if obj := rootDict.Get("OpenAction"); obj != nil {
		if analyzeObject(obj, visited, &mu) {
			return true
		}
	}

	// 修正AcroForm检测逻辑
	return checkFormFields(rootDict)
}

// checkFormFields 检查表单字段是否包含XSS风险
// 参数:
//   - rootDict: PDF的Root字典
//
// 返回:
//   - bool: 如果检测到XSS风险返回true，否则返回false
func checkFormFields(rootDict *core.PdfObjectDictionary) bool {
	// 获取AcroForm字典
	acroForm, ok := core.GetDict(rootDict.Get("AcroForm"))
	if !ok {
		return false
	}

	// 字段数组检测（安全类型转换）
	fields, ok := core.GetArray(acroForm.Get("Fields"))
	if !ok || fields.Len() == 0 {
		return false
	}

	// 并行检测字段对象
	var wg sync.WaitGroup
	resultChan := make(chan bool, 10)

	for _, fieldObj := range fields.Elements() {
		wg.Add(1)
		go func(obj core.PdfObject) {
			defer wg.Done()
			if analyzeField(obj, make(map[core.PdfObject]struct{})) {
				resultChan <- true
			}
		}(core.TraceToDirectObject(fieldObj)) // 解决间接引用问题
	}

	// 结果监听
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	return <-resultChan != false
}

// analyzeField 分析表单字段是否包含XSS风险
// 参数:
//   - obj: 要分析的字段对象
//   - visited: 已访问对象记录
//
// 返回:
//   - bool: 如果检测到XSS风险返回true，否则返回false
func analyzeField(obj core.PdfObject, visited map[core.PdfObject]struct{}) bool {
	if obj == nil {
		return false
	}

	// 防止循环引用
	if _, exists := visited[obj]; exists {
		return false
	}
	visited[obj] = struct{}{}

	// 处理字段字典
	fieldDict, ok := core.GetDict(obj)
	if !ok {
		return false
	}

	var mu sync.Mutex

	// 检测子字段
	if kids, ok := core.GetArray(fieldDict.Get("Kids")); ok {
		for _, kid := range kids.Elements() {
			if analyzeField(kid, visited) {
				return true
			}
		}
	}

	// 动作检测（Submit/Reset）
	if aa, ok := core.GetDict(fieldDict.Get("A")); ok {
		if analyzeObject(aa, visited, &mu) {
			return true
		}
	}

	// 字段值检测
	return analyzeObject(fieldDict, visited, &mu)
}

// detectPDFXSSFromFileByte 从字节数组检测PDF是否包含XSS风险
// 参数:
//   - fileByte: PDF文件的字节数组
//
// 返回:
//   - bool: 如果检测到XSS风险返回true，否则返回false
//   - error: 如果检测过程中发生错误返回错误信息
func detectPDFXSSFromFileByte(fileByte []byte) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), configManager.timeoutDuration)
	defer cancel()

	// 使用bytes.NewReader创建io.ReadSeeker
	reader := bytes.NewReader(fileByte)

	// 快速检测层
	if found, err := fastDetectionFromBytes(reader); found || err != nil {
		return found, err
	}

	// 深度检测层
	return deepDetectionFromBytes(ctx, reader)
}

// fastDetectionFromBytes 从字节数组快速检测PDF是否包含XSS风险
// 参数:
//   - reader: 字节数组读取器
//
// 返回:
//   - bool: 如果检测到XSS风险返回true，否则返回false
//   - error: 如果检测过程中发生错误返回错误信息
func fastDetectionFromBytes(reader *bytes.Reader) (bool, error) {
	firstTime := time.Now().Local()
	defer func() {
		log.Printf("fastDetectionFromBytes Scanning time %.2fs ", time.Now().Local().Sub(firstTime).Seconds())
	}()

	_, _ = reader.Seek(0, 0)
	pdfReader, err := model.NewPdfReader(reader)
	if err != nil {
		return false, fmt.Errorf("创建PDF读取器失败: %v", err)
	}

	// 获取Catalog字典
	catalogDict, err := getCatalogDict(pdfReader)
	if err != nil {
		return false, err
	}

	// 检查Catalog中的关键区域
	if checkCatalogObjects(catalogDict) {
		return true, nil
	}

	// 2. 快速页面扫描
	return quickPageCheck(pdfReader, 3)
}

// deepDetectionFromBytes 从字节数组深度检测PDF是否包含XSS风险，带超时控制
// 参数:
//   - ctx: 上下文，用于控制超时
//   - reader: 字节数组读取器
//
// 返回:
//   - bool: 如果检测到XSS风险返回true，否则返回false
//   - error: 如果检测过程中发生错误返回错误信息
func deepDetectionFromBytes(ctx context.Context, reader *bytes.Reader) (bool, error) {
	result := make(chan bool, 1)
	errChan := make(chan error, 1)

	go func() {
		reader.Seek(0, 0)
		pdfReader, err := model.NewPdfReader(reader)
		if err != nil {
			errChan <- fmt.Errorf("创建PDF读取器失败: %v", err)
			return
		}

		// 全对象扫描
		result <- fullObjectScan(pdfReader)
	}()

	select {
	case <-ctx.Done():
		return false, fmt.Errorf("检测超时")
	case err := <-errChan:
		return false, err
	case found := <-result:
		return found, nil
	}
}
