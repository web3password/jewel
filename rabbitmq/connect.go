/*
Copyright (C) 2024 Web3Password PTE. LTD.(Singapore UEN: 202333030C) - All Rights Reserved

Web3Password PTE. LTD.(Singapore UEN: 202333030C) holds the copyright of this file.

Unauthorized copying or redistribution of this file in binary forms via any medium is strictly prohibited.

For more information, please refer to https://www.web3password.com/web3password_license.txt
*/

package rabbitmq

import (
	"crypto/tls"
	"fmt"
	"github.com/web3password/jewel/slicex"
	"net/url"
	"sync"
	"time"

	amqp "github.com/rabbitmq/amqp091-go"
	"github.com/web3password/jewel/tools"
	"golang.org/x/exp/slices"
)

const (
	// defaultCheckInterval .
	defaultCheckInterval = 3 * time.Second
)

// ConnectPool connect pool
type ConnectPool struct {
	checkInterval    time.Duration
	registerConnect  []*connect
	availableConnect sync.Map
	availableHost    []string
}

type connect struct {
	addr      string
	host      string
	scheme    string
	enableTLS bool
	tlsConfig ClientTLS
	conn      *amqp.Connection
}

// Register register connect
func Register(confList []Config) (*ConnectPool, error) {
	if len(confList) == 0 {
		return nil, fmt.Errorf("time: %s, conf is empty", tools.GetDatetime())
	}
	pool := &ConnectPool{
		checkInterval:    defaultCheckInterval,
		registerConnect:  make([]*connect, 0, 50),
		availableConnect: sync.Map{},
	}
	for _, conf := range confList {
		u, err := url.Parse(conf.Addr)
		if err != nil {
			return nil, err
		}
		pool.registerConnect = append(pool.registerConnect, &connect{
			addr:      conf.Addr,
			host:      u.Host,
			scheme:    u.Scheme,
			enableTLS: conf.EnableTLS,
			tlsConfig: ClientTLS{
				Ca:  conf.TLSConfig.Ca,
				Crt: conf.TLSConfig.Crt,
				Key: conf.TLSConfig.Key,
			},
			conn: nil,
		})
	}
	pool.init()
	go pool.watch()
	return pool, nil
}

// LoadConnect load one connect
func (pool *ConnectPool) LoadConnect() (*amqp.Connection, string, error) {
	var (
		conn *connect
	)

	for _, host := range pool.availableHost {
		avaConn, err := pool.load(host)
		if err != nil {
			continue
		}
		if avaConn == nil {
			continue
		}
		conn = avaConn
	}
	if conn == nil {
		return nil, "", fmt.Errorf("time: %s, no availabel conn", tools.GetDatetime())
	}
	return conn.conn, conn.connectInfo(), nil
}

func (pool *ConnectPool) DumpRunTimeConfig(host string) (*RunTimeConfig, error) {
	conn, err := pool.load(host)
	if err != nil {
		return nil, err
	}
	if conn == nil {
		return nil, fmt.Errorf("time: %s, conn is nil", tools.GetDatetime())
	}
	return &RunTimeConfig{
		Host:      conn.host,
		Scheme:    conn.scheme,
		EnableTLS: conn.enableTLS,
		TLSConfig: ClientTLS{
			Ca:  conn.tlsConfig.Ca,
			Crt: conn.tlsConfig.Crt,
			Key: conn.tlsConfig.Key,
		},
	}, nil
}

func (pool *ConnectPool) init() {
	for _, node := range pool.registerConnect {
		host := node.connectInfo()
		conn, err := pool.load(host)
		if err != nil {
			fmt.Printf("time: %s, connect pool load addr err, remove from available host:%s\n", tools.GetDatetime(), host)
			pool.remove(host)
			continue
		}
		if conn != nil {
			if isClosed := conn.isClosed(); isClosed {
				pool.remove(host)
				fmt.Printf("time: %s, connect is closed, remove from available host:%s\n", tools.GetDatetime(), host)
				continue
			}
			fmt.Printf("time: %s, connect is health host:%s\n", tools.GetDatetime(), host)
			pool.store(host, conn)
			continue
		}
		if err := node.connect(); err != nil {
			fmt.Printf("time: %s, connect fail host:%s err:%+v\n", tools.GetDatetime(), host, err)
			continue
		}
		pool.store(host, node)
		fmt.Printf("time: %s, connect success host:%s\n", tools.GetDatetime(), host)
	}
}

func (pool *ConnectPool) watch() {
	for {
		pool.init()
		pool.availableHost = slicex.Unique(pool.availableHost)
		fmt.Printf(">>>time: %s, checkInterval: %v, default checkInterval: %v \n", tools.GetDatetime(), pool.checkInterval, defaultCheckInterval)
		time.Sleep(pool.checkInterval)
	}
}

func (pool *ConnectPool) store(host string, conn *connect) {
	pool.availableConnect.Store(host, conn)
	index := slices.Index(pool.availableHost, host)
	if index == -1 {
		pool.availableHost = append(pool.availableHost, host)
	}
}

func (pool *ConnectPool) load(host string) (*connect, error) {
	val, ok := pool.availableConnect.Load(host)
	if !ok {
		return nil, nil
	}
	conn, ok := val.(*connect)
	if !ok {
		return nil, fmt.Errorf("time: %s, error connect type host:%s", tools.GetDatetime(), host)
	}
	return conn, nil
}

func (pool *ConnectPool) remove(host string) {
	availableHost := make([]string, 0, len(pool.availableHost))
	for _, item := range pool.availableHost {
		if item == host {
			continue
		}
		availableHost = append(availableHost, item)
	}
	pool.availableHost = availableHost
	pool.availableConnect.Delete(host)
}

func (c *connect) connectInfo() string {
	return c.scheme + "//" + c.host
}

func (c *connect) connect() (err error) {
	var tlsConfig *tls.Config
	host := c.connectInfo()
	if c.enableTLS {
		tlsConfig, err = tools.TLSClientConfig(c.tlsConfig.Ca, c.tlsConfig.Crt, c.tlsConfig.Key)
		if err != nil {
			fmt.Printf("time: %s, LoadX509KeyPair host:%s err:%+v\n", tools.GetDatetime(), host, err)
			return err
		}
	}
	c.conn, err = amqp.DialConfig(c.addr, amqp.Config{
		Heartbeat:       5 * time.Second,
		TLSClientConfig: tlsConfig,
	})
	if err != nil {
		fmt.Printf("time:%s, rabbitmq connect fail host:%s err:%+v\n", tools.GetDatetime(), host, err)
		return err
	}
	return nil
}

func (c *connect) isClosed() bool {
	return c.conn.IsClosed()
}
