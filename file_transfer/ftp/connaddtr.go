package ftp

type ConnectFunc func(*ConnectCfg)

func WithAddress(address string) ConnectFunc {
	return func(cfg *ConnectCfg) {
		cfg.Address = address
	}
}

func WithUserName(userName string) ConnectFunc {
	return func(cfg *ConnectCfg) {
		cfg.UserName = userName
	}
}

func WithPwd(pwd string) ConnectFunc {
	return func(cfg *ConnectCfg) {
		cfg.Pwd = pwd
	}
}

type ConnectFuncs []ConnectFunc

func (c ConnectFuncs) apply(cfg *ConnectCfg) {
	for _, f := range c {
		f(cfg)
	}
}

// NewCfg 初始化连接配置信息
func NewCfg(fn ...ConnectFunc) *ConnectCfg {
	cfg := new(ConnectCfg)
	ConnectFuncs(fn).apply(cfg)
	return cfg
}
