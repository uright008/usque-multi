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
	accounts     []*Account
	mu           sync.Mutex
	minExtra     int
	registerFunc func() (*config.Config, error)
}

// Account 表示池中的单个账户
type Account struct {
	Config    *config.Config
	InUse     bool
	LastUsed  time.Time
	tlsConfig *TlsConfigWrapper
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
func NewAccountPool(minExtra int, registerFunc func() (*config.Config, error)) *AccountPool {
	pool := &AccountPool{
		accounts:     make([]*Account, 0),
		minExtra:     minExtra,
		registerFunc: registerFunc,
	}

	// 启动后台 goroutine 来维护账户池
	go pool.maintainPool()

	return pool
}

// GetAccount 获取一个可用账户
func (ap *AccountPool) GetAccount() (*Account, error) {
	ap.mu.Lock()
	defer ap.mu.Unlock()

	// 查找一个未使用的账户
	for _, account := range ap.accounts {
		if !account.InUse {
			account.InUse = true
			account.LastUsed = time.Now()
			return account, nil
		}
	}

	// 如果没有可用账户，注册一个新账户
	log.Printf("No available accounts, registering a new one...")
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
	return account, nil
}

// ReleaseAccount 释放账户，使其可再次使用
func (ap *AccountPool) ReleaseAccount(account *Account) {
	ap.mu.Lock()
	defer ap.mu.Unlock()

	account.InUse = false
}

// maintainPool 维护账户池，确保有足够的账户
func (ap *AccountPool) maintainPool() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		ap.checkAndRefill()
	}
}

// checkAndRefill 检查并补充账户池
func (ap *AccountPool) checkAndRefill() {
	ap.mu.Lock()
	defer ap.mu.Unlock()

	// 计算当前正在使用的账户数
	inUseCount := 0
	for _, account := range ap.accounts {
		if account.InUse {
			inUseCount++
		}
	}

	// 计算需要补充的账户数
	neededAccounts := inUseCount + ap.minExtra - len(ap.accounts)

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
}

// GetAccountCount 返回池中账户总数和正在使用的账户数
func (ap *AccountPool) GetAccountCount() (total, inUse int) {
	ap.mu.Lock()
	defer ap.mu.Unlock()

	total = len(ap.accounts)
	for _, account := range ap.accounts {
		if account.InUse {
			inUse++
		}
	}

	return total, inUse
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
