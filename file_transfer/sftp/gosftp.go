package sftp

import (
	"errors"
	"fmt"
	"git.900sui.cn/kc/base/common/functions"
	"git.900sui.cn/kc/kcgin/logs"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"
)

// GoSftpClient 连接的配置
type GoSftpClient struct {
	*Config
	sshClient   *ssh.Client  // ssh client
	sftpClient  *sftp.Client // sftp client
	LastResult  string       //最近一次运行的结果
	BodyContent []byte       // 读取的文件内容信息
}

type Config struct {
	Host     string        // ip
	Port     int64         // 端口
	Username string        // 用户名
	DstPath  string        // 下载到本地的文件目录
	Timeout  time.Duration // 超时时间，默认为10s
}

type AuthOption func(*ssh.ClientConfig)

// WithPrivateKey 设置私钥（ssh身份验证方法之一）
//
//	privateKey：私钥字符串；isPemFormat：私钥字符串是否是pem格式
func WithPrivateKey(privateKey string, isPemFormat bool) AuthOption {
	return func(config *ssh.ClientConfig) {
		if !isPemFormat {
			privateKey = functions.GetPemPrivate(privateKey)
		}
		// Create the Signer for this private key.
		signer, err := ssh.ParsePrivateKey([]byte(privateKey))
		if err != nil {
			logs.Error("unable to parse private key: %v", err)
			return
		}
		config.Auth = []ssh.AuthMethod{ssh.PublicKeys(signer)}
	}
}

// WithPassword 设置密码（ssh身份验证方法之一）
func WithPassword(password string) AuthOption {
	return func(config *ssh.ClientConfig) {
		config.Auth = []ssh.AuthMethod{ssh.Password(password)}
	}
}

func checkConfigParams(conf *Config) error {
	if len(conf.Host) == 0 {
		return errors.New("host is empty")
	}
	if conf.Port == 0 {
		return errors.New("port is empty")
	}
	if len(conf.Username) == 0 {
		return errors.New("userName is empty")
	}
	if conf.Timeout == 0 {
		conf.Timeout = 10 * time.Second
	}
	return nil
}

// NewSftpClient 创建一个新的GoSftpClient客户端
func NewSftpClient(conf *Config, authOptions ...AuthOption) (*GoSftpClient, error) {

	if err := checkConfigParams(conf); err != nil {
		return nil, err
	}

	var (
		sshClient  *ssh.Client
		sftpClient *sftp.Client
		err        error
	)

	gsClient := new(GoSftpClient)
	gsClient.Config = conf

	config := &ssh.ClientConfig{
		User: conf.Username,
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			return nil
		},
		Timeout: conf.Timeout,
	}

	for _, authOption := range authOptions {
		authOption(config)
	}

	if len(config.Auth) == 0 {
		return nil, errors.New("ssh auth is empty")
	}

	addr := fmt.Sprintf("%s:%d", gsClient.Host, gsClient.Port)

	if sshClient, err = ssh.Dial("tcp", addr, config); err != nil {
		return nil, err
	}
	gsClient.sshClient = sshClient

	// 此时获取了sshClient，下面使用sshClient构建sftpClient
	if sftpClient, err = sftp.NewClient(sshClient); err != nil {
		return nil, err
	}
	gsClient.sftpClient = sftpClient
	return gsClient, nil
}

// RunShell 运行shell脚本
func (g *GoSftpClient) RunShell(shell string) string {
	if strings.TrimSpace(shell) == "" {
		return ""
	}

	var (
		session *ssh.Session
		err     error
	)

	// 获取session，这个session是用来远程执行操作的
	if session, err = g.sshClient.NewSession(); err != nil {
		log.Fatalln("error occurred:", err)
	}
	// 执行shell
	if output, err := session.CombinedOutput(shell); err != nil {
		fmt.Println(shell)
		log.Fatalln("error occurred:", err)
	} else {
		g.LastResult = string(output)
	}
	return g.LastResult
}

// UploadFile 上传文件
//
//	srcPath：源文件；dstPath：目标文件
func (g *GoSftpClient) UploadFile(srcPath, dstPath string) error {
	srcFile, _ := os.Open(srcPath) //本地
	// 创建远程上传文件路径
	if _, err := g.CreateRemoteFilePath(dstPath); err != nil {
		return err
	}
	dstFile, er := g.sftpClient.Create(dstPath) //远程
	if er != nil {
		return er
	}
	defer func() {
		_ = srcFile.Close()
		_ = dstFile.Close()
	}()
	buf := make([]byte, 1024)
	for {
		n, err := srcFile.Read(buf)
		if err != nil {
			if err != io.EOF {
				log.Fatalln("error occurred:", err)
				return err
			} else {
				break
			}
		}
		if _, err = dstFile.Write(buf[:n]); err != nil {
			return err
		}
	}
	fmt.Println(fmt.Sprintf("ls %s", dstPath))
	//fmt.Println(SftpClient.RunShell(fmt.Sprintf("ls %s", dstPath)))
	return nil
}

// LocalPathExists 本地文件路径是否存在
func LocalPathExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

// CheckFileExist 判断所给路径文件/文件夹是否存在
func CheckFileExist(fileName string) bool {
	_, err := os.Stat(fileName)
	if err != nil {
		if os.IsExist(err) {
			return true
		}
		return false
	}
	return true
}

// CreateLocalFilePath 创建本地文件
func CreateLocalFilePath(path string) (bool, error) {
	if path == "" {
		return false, fmt.Errorf("下载路径必须传递")
	}
	dir := strings.Split(path, "/")
	dir = dir[0 : len(dir)-1]
	_dir := strings.Join(dir, "/")

	exist, err := LocalPathExists(_dir)
	if err != nil {
		return false, err
	}
	if !exist {
		err = os.MkdirAll(_dir, os.ModePerm)
		if err != nil {
			return false, err
		}
	}
	return true, nil
}

// RemotePathExists 远程文件路径是否存在
func (g *GoSftpClient) RemotePathExists(remotePath string) (bool, error) {
	_, err := g.sftpClient.Stat(remotePath)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

// CreateRemoteFilePath 创建远程文件
func (g *GoSftpClient) CreateRemoteFilePath(path string) (bool, error) {
	if path == "" {
		return false, fmt.Errorf("上传路径必须传递")
	}
	dir := strings.Split(path, "/")
	dir = dir[0 : len(dir)-1]
	_dir := strings.Join(dir, "/")

	exist, err := g.RemotePathExists(_dir)
	if err != nil {
		return false, err
	}
	if !exist {
		err = g.sftpClient.MkdirAll(_dir)
		if err != nil {
			return false, err
		}
	}
	return true, nil
}

// GetSftpContent 获取sftp内容
func (g *GoSftpClient) GetSftpContent() ([]byte, error) {
	return g.BodyContent, nil
}

// DownloadFile 下载源文件
//
//	srcPath 源文件
func (g *GoSftpClient) DownloadFile(srcPath string) error {
	//保存读取的信息
	logs.Info("DownloadFile srcPath :%s", srcPath)
	srcFile, err := g.sftpClient.Open(srcPath) // 远程
	if err != nil {
		return err
	}
	defer srcFile.Close()

	dstPath := g.Config.DstPath + srcPath // 目的 /logs/
	if _, err = CreateLocalFilePath(dstPath); err != nil {
		return err
	}

	dstFile, err := os.Create(dstPath) // 本地
	if err != nil {
		return err
	}
	defer dstFile.Close()
	if _, err = srcFile.WriteTo(dstFile); err != nil {
		return err
	}

	g.BodyContent, _ = os.ReadFile(dstPath)
	// 下载文件到本地成功
	return nil
}

// UploadImage 将服务器上的图片上传到指定的sftp服务器上
//
//	imgPath：原图片在服务器上的地址；localTempPath：图片临时路径；remotePath：远程sftp服务器图片存放目录
func (g *GoSftpClient) UploadImage(imgPath, localTempPath, remoteDir string) (string, error) {
	if _, err := CreateLocalFilePath(localTempPath); err != nil {
		return "", err
	}
	// 根据图片地址获取图片内容
	imageBody, err := RequestGet(imgPath)
	if err != nil {
		return "", err
	}

	imgUrlSlice := strings.Split(imgPath, "/")
	fileName := imgUrlSlice[len(imgUrlSlice)-1]
	if !strings.Contains(fileName, ".") {
		fileName = fmt.Sprintf("%s.jpg", fileName) // 文件名
	}
	localTempFilePath := filepath.Join(localTempPath, fileName) // 本地临时存储图片路径

	// 创建临时文件
	f, err := os.OpenFile(localTempFilePath, os.O_WRONLY|os.O_CREATE, 0666)
	if err != nil {
		return "", err
	}
	if _, err = f.Write([]byte(imageBody)); err != nil {
		return "", err
	}
	_ = f.Close()

	// 文件上传成功后，删除临时文件
	defer func() {
		_ = os.Remove(localTempFilePath)
	}()
	remotePath := path.Join(remoteDir, fileName)
	if err = g.UploadFile(localTempFilePath, remotePath); err != nil {
		return "", err
	}

	return remotePath, nil
}

// RequestGet GET 请求
func RequestGet(url string) (res string, err error) {
	var request *http.Request
	request, err = http.NewRequest("GET", url, nil)
	if err != nil {
		return
	}
	request.Header.Set("Content-Type", "application/json;charset=utf-8")
	request.Header.Set("Accept-Encoding", "*/*")
	client := &http.Client{}
	var response *http.Response
	response, err = client.Do(request)
	if err != nil {
		return
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusOK {
		body, _ := io.ReadAll(response.Body)
		res = string(body)
		return
	}
	err = errors.New("request status:" + response.Status + ",url :" + url)
	return
}
