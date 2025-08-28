package cmd

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Diniboy1123/usque/api"
	"github.com/Diniboy1123/usque/config"
	"github.com/Diniboy1123/usque/internal"
	"github.com/spf13/cobra"
	"github.com/things-go/go-socks5"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

var socksCmd = &cobra.Command{
	Use:   "socks",
	Short: "Expose Warp as a SOCKS5 proxy",
	Long:  "Dual-stack SOCKS5 proxy with optional authentication. Doesn't require elevated privileges.",
	Run: func(cmd *cobra.Command, args []string) {
		if !config.ConfigLoaded {
			cmd.Println("Config not loaded. Please register first.")
			return
		}

		// 解析命令行参数
		sni, err := cmd.Flags().GetString("sni-address")
		if err != nil {
			cmd.Printf("Failed to get SNI address: %v\n", err)
			return
		}

		bindAddress, err := cmd.Flags().GetString("bind")
		if err != nil {
			cmd.Printf("Failed to get bind address: %v\n", err)
			return
		}

		port, err := cmd.Flags().GetString("port")
		if err != nil {
			cmd.Printf("Failed to get port: %v\n", err)
			return
		}

		connectPort, err := cmd.Flags().GetInt("connect-port")
		if err != nil {
			cmd.Printf("Failed to get connect port: %v\n", err)
			return
		}

		tunnelIPv4, err := cmd.Flags().GetBool("no-tunnel-ipv4")
		if err != nil {
			cmd.Printf("Failed to get no tunnel IPv4: %v\n", err)
			return
		}

		tunnelIPv6, err := cmd.Flags().GetBool("no-tunnel-ipv6")
		if err != nil {
			cmd.Printf("Failed to get no tunnel IPv6: %v\n", err)
			return
		}

		dnsServers, err := cmd.Flags().GetStringArray("dns")
		if err != nil {
			cmd.Printf("Failed to get DNS servers: %v\n", err)
			return
		}

		var dnsAddrs []netip.Addr
		for _, dns := range dnsServers {
			addr, err := netip.ParseAddr(dns)
			if err != nil {
				cmd.Printf("Failed to parse DNS server: %v\n", err)
				return
			}
			dnsAddrs = append(dnsAddrs, addr)
		}

		var dnsTimeout time.Duration
		if dnsTimeout, err = cmd.Flags().GetDuration("dns-timeout"); err != nil {
			cmd.Printf("Failed to get DNS timeout: %v\n", err)
			return
		}

		localDNS, err := cmd.Flags().GetBool("local-dns")
		if err != nil {
			cmd.Printf("Failed to get local-dns flag: %v\n", err)
			return
		}

		mtu, err := cmd.Flags().GetInt("mtu")
		if err != nil {
			cmd.Printf("Failed to get MTU: %v\n", err)
			return
		}
		if mtu != 1280 {
			log.Println("Warning: MTU is not the default 1280. This is not supported. Packet loss and other issues may occur.")
		}

		var username string
		var password string
		if u, err := cmd.Flags().GetString("username"); err == nil && u != "" {
			username = u
		}
		if p, err := cmd.Flags().GetString("password"); err == nil && p != "" {
			password = p
		}

		keepalivePeriod, err := cmd.Flags().GetDuration("keepalive-period")
		if err != nil {
			cmd.Printf("Failed to get keepalive period: %v\n", err)
			return
		}
		initialPacketSize, err := cmd.Flags().GetUint16("initial-packet-size")
		if err != nil {
			cmd.Printf("Failed to get initial packet size: %v\n", err)
			return
		}

		reconnectDelay, err := cmd.Flags().GetDuration("reconnect-delay")
		if err != nil {
			cmd.Printf("Failed to get reconnect delay: %v\n", err)
			return
		}

		ipv6, err := cmd.Flags().GetBool("ipv6")
		if err != nil {
			cmd.Printf("Failed to get ipv6 flag: %v\n", err)
			return
		}

		// 创建自定义的 Dial 函数，为每个连接使用单独的账户
		var connectionCount int64

		// 创建账户池，确保至少有连接数+1个账户
		accountPool := api.NewAccountPool(1, api.RegisterNewAccount, func() int {
			return int(atomic.LoadInt64(&connectionCount))
		})

		// 创建 SOCKS5 服务器
		var resolver socks5.NameResolver
		if localDNS {
			resolver = internal.TunnelDNSResolver{TunNet: nil, DNSAddrs: dnsAddrs, Timeout: dnsTimeout}
		} else {
			// 对于动态代理，我们需要为每个连接创建 resolver
			resolver = nil
		}

		var server *socks5.Server
		if username == "" || password == "" {
			server = socks5.NewServer(
				socks5.WithLogger(socks5.NewLogger(log.New(os.Stdout, "socks5: ", log.LstdFlags))),
				socks5.WithDial(func(ctx context.Context, network, addr string) (net.Conn, error) {
					count := atomic.AddInt64(&connectionCount, 1)
					log.Printf("Handling connection #%d to %s", count, addr)

					// 从账户池获取账户
					account, err := accountPool.GetAccount()
					if err != nil {
						atomic.AddInt64(&connectionCount, -1)
						log.Printf("Failed to get account from pool: %v", err)
						return nil, fmt.Errorf("failed to get account from pool: %v", err)
					}

					// 使用账户配置创建隧道
					conn, cleanup, err := createTunnelConnection(
						account.Config,
						addr,
						sni,
						connectPort,
						ipv6,
						tunnelIPv4,
						tunnelIPv6,
						dnsAddrs,
						mtu,
						keepalivePeriod,
						initialPacketSize,
						reconnectDelay,
						network,
					)
					if err != nil {
						atomic.AddInt64(&connectionCount, -1)
						accountPool.ReleaseAccount(account)
						log.Printf("Failed to create tunnel connection: %v", err)
						return nil, err
					}

					// 确保conn不为nil
					if conn == nil {
						atomic.AddInt64(&connectionCount, -1)
						accountPool.ReleaseAccount(account)
						if cleanup != nil {
							cleanup()
						}
						log.Printf("Tunnel connection is nil")
						return nil, fmt.Errorf("failed to create tunnel connection")
					}

					// 检查conn是否实现了必要的方法
					if conn.RemoteAddr() == nil {
						atomic.AddInt64(&connectionCount, -1)
						accountPool.ReleaseAccount(account)
						if cleanup != nil {
							cleanup()
						}
						log.Printf("Tunnel connection has nil RemoteAddr")
						return nil, fmt.Errorf("tunnel connection has nil RemoteAddr")
					}

					// 包装连接以在关闭时释放账户和减少计数
					wrappedConn := &accountTrackingConn{
						Conn:        conn,
						account:     account,
						accountPool: accountPool,
						count:       &connectionCount,
						cleanup:     cleanup,
					}

					log.Printf("Successfully created connection #%d to %s", count, addr)

					return wrappedConn, nil
				}),
				socks5.WithResolver(resolver),
			)
		} else {
			server = socks5.NewServer(
				socks5.WithLogger(socks5.NewLogger(log.New(os.Stdout, "socks5: ", log.LstdFlags))),
				socks5.WithDial(func(ctx context.Context, network, addr string) (net.Conn, error) {
					count := atomic.AddInt64(&connectionCount, 1)
					log.Printf("Handling connection #%d to %s", count, addr)

					// 从账户池获取账户
					account, err := accountPool.GetAccount()
					if err != nil {
						atomic.AddInt64(&connectionCount, -1)
						log.Printf("Failed to get account from pool: %v", err)
						return nil, fmt.Errorf("failed to get account from pool: %v", err)
					}

					// 使用账户配置创建隧道
					conn, cleanup, err := createTunnelConnection(
						account.Config,
						addr,
						sni,
						connectPort,
						ipv6,
						tunnelIPv4,
						tunnelIPv6,
						dnsAddrs,
						mtu,
						keepalivePeriod,
						initialPacketSize,
						reconnectDelay,
						network,
					)
					if err != nil {
						atomic.AddInt64(&connectionCount, -1)
						accountPool.ReleaseAccount(account)
						log.Printf("Failed to create tunnel connection: %v", err)
						return nil, err
					}

					// 确保conn不为nil
					if conn == nil {
						atomic.AddInt64(&connectionCount, -1)
						accountPool.ReleaseAccount(account)
						if cleanup != nil {
							cleanup()
						}
						log.Printf("Tunnel connection is nil")
						return nil, fmt.Errorf("failed to create tunnel connection")
					}

					// 检查conn是否实现了必要的方法
					if conn.RemoteAddr() == nil {
						atomic.AddInt64(&connectionCount, -1)
						accountPool.ReleaseAccount(account)
						if cleanup != nil {
							cleanup()
						}
						log.Printf("Tunnel connection has nil RemoteAddr")
						return nil, fmt.Errorf("tunnel connection has nil RemoteAddr")
					}

					// 包装连接以在关闭时释放账户和减少计数
					wrappedConn := &accountTrackingConn{
						Conn:        conn,
						account:     account,
						accountPool: accountPool,
						count:       &connectionCount,
						cleanup:     cleanup,
					}

					log.Printf("Successfully created connection #%d to %s", count, addr)

					return wrappedConn, nil
				}),
				socks5.WithResolver(resolver),
				socks5.WithAuthMethods(
					[]socks5.Authenticator{
						socks5.UserPassAuthenticator{
							Credentials: socks5.StaticCredentials{
								username: password,
							},
						},
					},
				),
			)
		}

		log.Printf("Dynamic SOCKS proxy listening on %s:%s", bindAddress, port)
		log.Printf("Each connection will use a separate account from the pool")
		if err := server.ListenAndServe("tcp", net.JoinHostPort(bindAddress, port)); err != nil {
			cmd.Printf("Failed to start SOCKS proxy: %v\n", err)
			return
		}
	},
}

// accountTrackingConn 包装连接以在关闭时释放账户和减少计数
type accountTrackingConn struct {
	net.Conn
	account     *api.Account
	accountPool *api.AccountPool
	count       *int64
	cleanup     func()
	once        sync.Once
}

// Close 关闭连接并释放账户
func (atc *accountTrackingConn) Close() error {
	var err error
	atc.once.Do(func() {
		// 关闭实际连接
		if atc.Conn != nil {
			err = atc.Conn.Close()
		}

		// 执行清理函数（关闭TUN设备，取消维护goroutine）
		if atc.cleanup != nil {
			atc.cleanup()
		}

		// 释放账户
		if atc.accountPool != nil && atc.account != nil {
			atc.accountPool.ReleaseAccount(atc.account)
		}

		// 减少连接计数
		if atc.count != nil {
			atomic.AddInt64(atc.count, -1)
		}
	})
	return err
}

// Read 实现net.Conn接口的Read方法
func (atc *accountTrackingConn) Read(b []byte) (n int, err error) {
	if atc.Conn == nil {
		return 0, fmt.Errorf("connection is nil")
	}
	return atc.Conn.Read(b)
}

// Write 实现net.Conn接口的Write方法
func (atc *accountTrackingConn) Write(b []byte) (n int, err error) {
	if atc.Conn == nil {
		return 0, fmt.Errorf("connection is nil")
	}
	return atc.Conn.Write(b)
}

// LocalAddr 实现net.Conn接口的LocalAddr方法
func (atc *accountTrackingConn) LocalAddr() net.Addr {
	if atc.Conn == nil {
		return nil
	}
	return atc.Conn.LocalAddr()
}

// RemoteAddr 实现net.Conn接口的RemoteAddr方法
func (atc *accountTrackingConn) RemoteAddr() net.Addr {
	if atc.Conn == nil {
		return nil
	}
	return atc.Conn.RemoteAddr()
}

// SetDeadline 实现net.Conn接口的SetDeadline方法
func (atc *accountTrackingConn) SetDeadline(t time.Time) error {
	if atc.Conn == nil {
		return fmt.Errorf("connection is nil")
	}
	return atc.Conn.SetDeadline(t)
}

// SetReadDeadline 实现net.Conn接口的SetReadDeadline方法
func (atc *accountTrackingConn) SetReadDeadline(t time.Time) error {
	if atc.Conn == nil {
		return fmt.Errorf("connection is nil")
	}
	return atc.Conn.SetReadDeadline(t)
}

// SetWriteDeadline 实现net.Conn接口的SetWriteDeadline方法
func (atc *accountTrackingConn) SetWriteDeadline(t time.Time) error {
	if atc.Conn == nil {
		return fmt.Errorf("connection is nil")
	}
	return atc.Conn.SetWriteDeadline(t)
}

// createTunnelConnection 为指定地址创建隧道连接
func createTunnelConnection(
	cfg *config.Config,
	addr string,
	sni string,
	connectPort int,
	ipv6 bool,
	tunnelIPv4 bool,
	tunnelIPv6 bool,
	dnsAddrs []netip.Addr,
	mtu int,
	keepalivePeriod time.Duration,
	initialPacketSize uint16,
	reconnectDelay time.Duration,
	network string,
) (net.Conn, func(), error) {
	// 获取私钥和公钥
	privKey, err := cfg.GetEcPrivateKey()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get private key: %v", err)
	}

	peerPubKey, err := cfg.GetEcEndpointPublicKey()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get public key: %v", err)
	}

	// 生成证书
	cert, err := internal.GenerateCert(privKey, &privKey.PublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate cert: %v", err)
	}

	// 准备 TLS 配置
	tlsConfig, err := api.PrepareTlsConfig(privKey, peerPubKey, cert, sni)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to prepare TLS config: %v", err)
	}

	// 确定端点地址
	var endpoint *net.UDPAddr
	if !ipv6 {
		endpoint = &net.UDPAddr{
			IP:   net.ParseIP(cfg.EndpointV4),
			Port: connectPort,
		}
	} else {
		endpoint = &net.UDPAddr{
			IP:   net.ParseIP(cfg.EndpointV6),
			Port: connectPort,
		}
	}

	// 设置本地地址
	var localAddresses []netip.Addr
	if !tunnelIPv4 {
		v4, err := netip.ParseAddr(cfg.IPv4)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to parse IPv4 address: %v", err)
		}
		localAddresses = append(localAddresses, v4)
	}
	if !tunnelIPv6 {
		v6, err := netip.ParseAddr(cfg.IPv6)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to parse IPv6 address: %v", err)
		}
		localAddresses = append(localAddresses, v6)
	}

	// 创建虚拟 TUN 设备
	tunDev, tunNet, err := netstack.CreateNetTUN(localAddresses, dnsAddrs, mtu)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create virtual TUN device: %v", err)
	}

	// 启动隧道维护 goroutine
	ctx, cancel := context.WithCancel(context.Background())
	go api.MaintainTunnel(ctx, tlsConfig, keepalivePeriod, initialPacketSize, endpoint, api.NewNetstackAdapter(tunDev), mtu, reconnectDelay)

	// 连接到目标地址
	conn, err := tunNet.DialContext(context.Background(), network, addr)
	if err != nil {
		cancel() // 取消维护goroutine
		tunDev.Close()
		return nil, nil, fmt.Errorf("failed to dial %s: %v", addr, err)
	}

	// 确保连接不为nil
	if conn == nil {
		cancel()
		tunDev.Close()
		return nil, nil, fmt.Errorf("dial succeeded but returned nil connection")
	}

	// 返回清理函数
	cleanup := func() {
		cancel() // 取消维护goroutine
		if conn != nil {
			conn.Close()
		}
		tunDev.Close()
	}

	return conn, cleanup, nil
}

func init() {
	socksCmd.Flags().StringP("bind", "b", "0.0.0.0", "Address to bind the SOCKS proxy to")
	socksCmd.Flags().StringP("port", "p", "1080", "Port to listen on for SOCKS proxy")
	socksCmd.Flags().StringP("username", "u", "", "Username for proxy authentication (specify both username and password to enable)")
	socksCmd.Flags().StringP("password", "w", "", "Password for proxy authentication (specify both username and password to enable)")
	socksCmd.Flags().IntP("connect-port", "P", 443, "Used port for MASQUE connection")
	socksCmd.Flags().StringArrayP("dns", "d", []string{"9.9.9.9", "149.112.112.112", "2620:fe::fe", "2620:fe::9"}, "DNS servers to use")
	socksCmd.Flags().DurationP("dns-timeout", "t", 2*time.Second, "Timeout for DNS queries")
	socksCmd.Flags().BoolP("ipv6", "6", false, "Use IPv6 for MASQUE connection")
	socksCmd.Flags().BoolP("no-tunnel-ipv4", "F", false, "Disable IPv4 inside the MASQUE tunnel")
	socksCmd.Flags().BoolP("no-tunnel-ipv6", "S", false, "Disable IPv6 inside the MASQUE tunnel")
	socksCmd.Flags().StringP("sni-address", "s", internal.ConnectSNI, "SNI address to use for MASQUE connection")
	socksCmd.Flags().DurationP("keepalive-period", "k", 30*time.Second, "Keepalive period for MASQUE connection")
	socksCmd.Flags().IntP("mtu", "m", 1280, "MTU for MASQUE connection")
	socksCmd.Flags().Uint16P("initial-packet-size", "i", 1242, "Initial packet size for MASQUE connection")
	socksCmd.Flags().DurationP("reconnect-delay", "r", 1*time.Second, "Delay between reconnect attempts")
	socksCmd.Flags().BoolP("local-dns", "l", false, "Don't use the tunnel for DNS queries")
}
