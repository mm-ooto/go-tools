# go-tools

## 项目介绍
`go-tools` 是一个基于 Go 语言开发的工具集合，旨在为开发者提供常见功能的实现，包括但不限于以下内容：
- **PDF 文件 XSS 漏洞检测**：提供检测和防护 XSS 漏洞的工具。
- **加密算法**：
  - RSA
  - AES
  - DES
  - 国密算法（SM 系列）
- **文件传输**：
  - SFTP
  - FTP
- **常用方法**：封装了一些开发中常用的工具方法。

## 使用方法
1. 克隆项目到本地：
   ```bash
   git clone https://github.com/mm-ooto/go-tools.git

2. 进入项目目录并安装依赖：
   ```bash
   cd go-tools-collection
   go mod tidy

3. 根据需要调用对应的工具方法。
