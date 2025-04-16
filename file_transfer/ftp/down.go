package ftp

import (
	"bytes"
	"fmt"
	"io"
)

// FileDownLoad 文件下载器
type FileDownLoad struct {
	Name    string // 文件名称
	Content []byte // 文件内容
}

// GetFile 下载文件
func (f *FileDownLoad) GetFile(r io.Reader) error {
	var buf = new(bytes.Buffer)
	_, err := io.Copy(buf, r)
	if err != nil {
		return err
	}
	var n = buf.Len()
	var res = []byte{}
	for {
		var b []byte
		switch {
		case n > 1024:
			b = make([]byte, 1024)
			n -= 1024
		default:
			b = make([]byte, n)
		}
		size, err := buf.Read(b)
		if err != nil && err != io.EOF {
			fmt.Println(err)
			return err
		}
		if size == 0 {
			break
		}
		res = append(res, b...)
	}
	f.Content = res
	return nil
}
