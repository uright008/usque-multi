package api

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/Diniboy1123/usque/config"
	"github.com/Diniboy1123/usque/internal"
)

// AccountPool 管理账户池，确保始终有足够的账户供SOCKS连接使用
type AccountPool struct {
	accounts        []*Account
	preRegistered   []*Account // 预注册账户
	totalRegistered int        // 已注册账户总数（包括预注册）
	mu              sync.Mutex
	minExtra        int
	maxTotal        int // 最大账户数限制
	registerFunc    func() (*config.Config, error)
}

// Account 表示池中的单个账户
type Account struct {
	Config    *config.Config
	InUse     bool
	LastUsed  time.Time
	tlsConfig *TlsConfigWrapper
	Conn      net.Conn
}

// TlsConfigWrapper 包装TLS配置和相关参数
type TlsConfigWrapper struct {
	TlsConfig         *tls.Config
	KeepalivePeriod   time.Duration
	InitialPacketSize uint16
	Endpoint          *net.UDPAddr
	MTU               int
	ReconnectDelay    time.Duration
}

// NewAccountPool 创建一个新的账户池
func NewAccountPool(minExtra int, maxTotal int, registerFunc func() (*config.Config, error), activeConnections func() int) *AccountPool {
	pool := &AccountPool{
		accounts:      make([]*Account, 0),
		preRegistered: make([]*Account, 0),
		minExtra:      minExtra,
		maxTotal:      maxTotal,
		registerFunc:  registerFunc,
	}

	// 初始预注册一些账户
	initialPreRegister := 5
	for i := 0; i < initialPreRegister; i++ {
		if config, err := registerFunc(); err == nil {
			pool.preRegistered = append(pool.preRegistered, &Account{
				Config:   config,
				InUse:    false,
				LastUsed: time.Now(),
			})
		}
	}

	// 启动后台 goroutine 来维护账户池
	pool.MaintainPool(activeConnections)

	return pool
}

// GetAccount 获取一个可用账户
func (ap *AccountPool) GetAccount() (*Account, error) {
	ap.mu.Lock()
	defer ap.mu.Unlock()

	// 首先尝试从主账户池获取未使用的账户
	for _, account := range ap.accounts {
		if !account.InUse {
			account.InUse = true
			account.LastUsed = time.Now()
			return account, nil
		}
	}

	// 如果主账户池为空，尝试从预注册账户中获取
	if len(ap.preRegistered) > 0 {
		account := ap.preRegistered[len(ap.preRegistered)-1]
		ap.accounts = append(ap.accounts, account)
		ap.preRegistered = ap.preRegistered[:len(ap.preRegistered)-1]
		account.InUse = true
		account.LastUsed = time.Now()
		log.Printf("Moved account from pre-registered to active pool")
		return account, nil
	}

	// 如果没有预注册账户且主账户池已满，检查是否可以注册新账户
	if ap.totalRegistered < ap.maxTotal {
		log.Printf("No pre-registered accounts available, registering a new one...")
		newConfig, err := ap.registerFunc()
		if err != nil {
			return nil, fmt.Errorf("failed to register new account: %v", err)
		}

		account := &Account{
			Config:   newConfig,
			InUse:    true,
			LastUsed: time.Now(),
		}

		ap.accounts = append(ap.accounts, account)
		ap.totalRegistered++
		return account, nil
	}

	return nil, fmt.Errorf("no available accounts and maximum account limit reached")
}

// ReleaseAccount 释放账户，使其可再次使用
func (ap *AccountPool) ReleaseAccount(account *Account) {
	ap.mu.Lock()
	defer ap.mu.Unlock()

	account.InUse = false
}

// MaintainPool 维护账户池，确保有足够的账户
func (ap *AccountPool) MaintainPool(activeConnections func() int) {
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()

		for range ticker.C {
			ap.checkAndRefill(activeConnections)
		}
	}()
}

// checkAndRefill 检查并补充账户池
func (ap *AccountPool) checkAndRefill(activeConnections func() int) {
	ap.mu.Lock()
	defer ap.mu.Unlock()

	// 获取当前活跃连接数
	activeConns := activeConnections()

	// 计算需要补充的账户数，确保至少有 activeConnections + minExtra 个账户
	neededAccounts := activeConns + ap.minExtra - len(ap.accounts)

	// 如果需要的账户数大于0，则注册新账户
	for i := 0; i < neededAccounts; i++ {
		log.Printf("Adding new account to pool...")
		newConfig, err := ap.registerFunc()
		if err != nil {
			log.Printf("Failed to register new account for pool: %v", err)
			continue
		}

		account := &Account{
			Config:   newConfig,
			InUse:    false,
			LastUsed: time.Now(),
		}

		ap.accounts = append(ap.accounts, account)
		log.Printf("Added new account to pool. Total accounts: %d", len(ap.accounts))
	}

	// 如果账户过多，可以考虑清理一些最老的未使用账户
	// 但为了简单起见，我们不实现这个功能
}

// GetAccountCount 返回池中账户总数、正在使用的账户数、预注册账户数
func (ap *AccountPool) GetAccountCount() (total, inUse, preRegistered int) {
	ap.mu.Lock()
	defer ap.mu.Unlock()

	total = len(ap.accounts)
	preRegistered = len(ap.preRegistered)
	for _, account := range ap.accounts {
		if account.InUse {
			inUse++
		}
	}

	return total, inUse, preRegistered
}

// GetActiveConnections 返回当前活跃连接数
func (ap *AccountPool) GetActiveConnections() int {
	return 0
}

// RegisterNewAccount 注册新账户的实现
func RegisterNewAccount() (*config.Config, error) {
	// 使用默认参数注册账户
	accountData, err := Register(internal.DefaultModel, internal.DefaultLocale, "", true)
	if err != nil {
		return nil, fmt.Errorf("failed to register account: %v", err)
	}

	// 生成密钥对
	privKey, pubKey, err := internal.GenerateEcKeyPair()
	if err != nil {
		return nil, fmt.Errorf("failed to generate key pair: %v", err)
	}

	// 注册设备密钥
	updatedAccountData, apiErr, err := EnrollKey(accountData, pubKey, "")
	if err != nil {
		if apiErr != nil {
			return nil, fmt.Errorf("failed to enroll key: %v (API errors: %s)", err, apiErr.ErrorsAsString("; "))
		} else {
			return nil, fmt.Errorf("failed to enroll key: %v", err)
		}
	}

	// 创建配置
	newConfig := &config.Config{
		PrivateKey: internal.EncodeBase64(privKey),
		// TODO: proper endpoint parsing in utils
		// strip :0
		EndpointV4: updatedAccountData.Config.Peers[0].Endpoint.V4[:len(updatedAccountData.Config.Peers[0].Endpoint.V4)-2],
		// strip [ from beginning and ]:0 from end
		EndpointV6:     updatedAccountData.Config.Peers[0].Endpoint.V6[1 : len(updatedAccountData.Config.Peers[0].Endpoint.V6)-3],
		EndpointPubKey: updatedAccountData.Config.Peers[0].PublicKey,
		License:        updatedAccountData.Account.License,
		ID:             updatedAccountData.ID,
		AccessToken:    accountData.Token,
		IPv4:           updatedAccountData.Config.Interface.Addresses.V4,
		IPv6:           updatedAccountData.Config.Interface.Addresses.V6,
	}

	return newConfig, nil
}
