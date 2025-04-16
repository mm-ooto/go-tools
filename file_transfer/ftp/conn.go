package ftp

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"

	"git.900sui.cn/kc/kcgin/logs"
	"github.com/dutchcoders/goftp"
)

type GoFtpClient struct {
	ftp             *goftp.FTP
	AccStmtDownLoad Download                                        // 处理业务器
	fileGetFromFtp  *FileDownLoad                                   // 内嵌如一个ftp下载器
	httpDownload    func(content string, path string) (bool, error) // 默认内部将下载的内容进行下载的http下载器
	path            string
}

// Conn 返回ftp指针
func (g *GoFtpClient) Conn() *goftp.FTP {
	return g.ftp
}

var ftp *goftp.FTP
var err error

// ConnectCfg 连接配置
type ConnectCfg struct {
	Address string
	AuthCfg
}

// AuthCfg 认证配置
type AuthCfg struct {
	UserName string
	Pwd      string
}

// NewGoFtpClient 创建一个新的GoFtpClient客户端
func NewGoFtpClient(cfg *ConnectCfg, dstPath string, fn ...Download) (*GoFtpClient, error) {
	ftp, err = goftp.Connect(cfg.Address)
	if err != nil {
		return nil, err
	}
	err = ftp.Login(cfg.UserName, cfg.Pwd)
	if err != nil {
		return nil, err
	}
	if len(fn) > 0 {
		return &GoFtpClient{ftp: ftp, AccStmtDownLoad: fn[0], httpDownload: httpDownload, path: dstPath}, nil
	}
	return &GoFtpClient{ftp: ftp, AccStmtDownLoad: nil, fileGetFromFtp: &FileDownLoad{Name: "下载器"}, httpDownload: httpDownload, path: dstPath}, nil
}

// 默认内部进行接收到数据进行校验处理 下载是其他处理
// 进行按对应的解析数据 可以进行注入进来即可 外部可以注入我们的方法
// 进行处理 解密和切割处理任务
func (g *GoFtpClient) processFile(content string) (string, error) {
	//这里进行业务处理 数据读取的进行校验和处理
	return content, nil
}

// BodyContent 返回读取的内容信息
func (g *GoFtpClient) BodyContent() ([]byte, error) {
	return g.fileGetFromFtp.Content, nil
}

// GetPath 返回path
func (g *GoFtpClient) GetPath() string {
	return g.path
}

// Content 返回对应的文件的io读取流信息
func (g *GoFtpClient) Content(path string) (*bytes.Buffer, error) {
	_, err := g.ftp.Retr(path, g.fileGetFromFtp.GetFile)
	if err != nil {
		return nil, err
	}
	return bytes.NewBuffer(g.fileGetFromFtp.Content), nil
}

// DownLoad 下载
func (g *GoFtpClient) DownLoad(path string) (bool, error) {
	// 下载对应的文件路径 下载到content
	// 如果不为空则处理即可
	_, err := g.ftp.Retr(path, g.fileGetFromFtp.GetFile)
	if err != nil {
		return false, err
	}

	if g.AccStmtDownLoad != nil {
		content, err := g.AccStmtDownLoad(string(g.fileGetFromFtp.Content))
		if err != nil {
			return false, err
		}
		return g.httpDownload(content, g.path)
	}
	content, err := g.processFile(string(g.fileGetFromFtp.Content))
	if err != nil {
		return false, err
	}
	return g.httpDownload(content, g.path)

}

// Close 关闭ftp连接
func (g *GoFtpClient) Close() {
	g.ftp.Close()
}

type Download func(string) (string, error)

// PathExists 判断文件夹是否存在
func PathExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

// httpDownload http下载
//
//	context：读取的内容信息，path 下载到文件名称.json .txt 具体的文件全名称
func httpDownload(context string, path string) (bool, error) {
	if path == "" {
		return false, fmt.Errorf("下载路径必须传递")
	}
	dir := strings.Split(path, "/")
	dir = dir[0 : len(dir)-1]
	_dir := strings.Join(dir, "/")

	exist, err := PathExists(_dir)
	if err != nil {
		return false, err
	}
	if !exist {
		err = os.MkdirAll(_dir, os.ModePerm)
		if err != nil {
			return false, err
		}
	}
	out, err := os.Create(path)
	if err != nil {
		return false, err
	}
	defer out.Close()
	// 拷贝stream流信息
	_, err = io.Copy(out, strings.NewReader(context))
	if err != nil {
		return false, err
	}
	logs.Info("下载成功!")
	return true, nil
}
