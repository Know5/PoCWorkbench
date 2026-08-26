package engine

import (
	"bufio"
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"pocworkbench/internal/model"
)

// listenTCP 启动一个按行回显的迷你 TCP 服务，responder 决定对输入的响应。
func listenTCP(t *testing.T, responder func(in string) string) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				var sb strings.Builder
				reader := bufio.NewReader(c)
				buf := make([]byte, 4096)
				for {
					n, err := reader.Read(buf)
					if n > 0 {
						sb.Write(buf[:n])
						if resp := responder(sb.String()); resp != "" {
							c.Write([]byte(resp))
							return
						}
					}
					if err != nil {
						return
					}
				}
			}(conn)
		}
	}()
	return ln
}

func portOf(addr string) string {
	i := strings.LastIndex(addr, ":")
	if i < 0 {
		return addr
	}
	return addr[i+1:]
}

// 回归：对端 accept 后从不读取时，conn.Write 不能无限阻塞（此前无 SetWriteDeadline，
// MaxConc=1 下单个 tarpit 目标即可永久卡死引擎）。写超时应使执行以 error 结束。
func TestExecTCPTarpitWriteDeadline(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 4096)
				for {
					if _, err := c.Read(buf); err != nil { // 只读不回：读缓冲很快塞满
						return
					}
				}
			}(conn)
		}
	}()

	e := New(Options{RunTimeout: 5 * time.Second, MaxConc: 1})
	spec := &model.Spec{
		Transport: "tcp",
		Rules: map[string]model.Rule{
			"r0": {Request: model.Request{Inputs: []model.TCPInput{{Data: strings.Repeat("A", 1<<20)}}}, Expression: `response.raw.bcontains(b'x')`},
		},
		Expression: "r0()",
	}
	done := make(chan RunResult, 1)
	go func() {
		done <- e.Run(context.Background(), spec, "tcp://"+ln.Addr().String())
	}()
	select {
	case res := <-done:
		if res.Result == "" {
			t.Fatal("应有明确结果分类")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Write 无限阻塞：tarpit 卡死引擎")
	}
}

// 回归：TCP 传输挂 http:// 代理须走 CONNECT 隧道；非法/不支持的代理须显式报错而非静默直连。
func TestExecTCPHTTPProxyConnect(t *testing.T) {
	// 迷你 CONNECT 代理：握手通过后伪装成目标服务，直接回 rsync banner
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				br := bufio.NewReader(c)
				line, err := br.ReadString('\n')
				if err != nil || !strings.HasPrefix(line, "CONNECT ") {
					return
				}
				for {
					l, err := br.ReadString('\n')
					if err != nil || l == "\r\n" {
						break
					}
				}
				c.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
				c.Write([]byte("@RSYNCD: OK\n"))
				buf := make([]byte, 4096)
				for {
					if _, err := c.Read(buf); err != nil {
						return
					}
				}
			}(conn)
		}
	}()

	e := New(Options{RunTimeout: 10 * time.Second})
	spec := &model.Spec{
		Transport: "tcp",
		Rules: map[string]model.Rule{
			"r0": {Request: model.Request{Inputs: []model.TCPInput{{Data: "@RSYNCD: QUIT\n"}}}, Expression: `response.raw.bcontains(b'@RSYNCD: ')`},
		},
		Expression: "r0()",
	}
	target := "tcp://target.invalid:873" // 代理不校验目标，拨号全走 CONNECT

	// http:// 代理 → CONNECT 隧道 → 命中 banner
	res := e.RunSink(context.Background(), spec, target, "http://"+ln.Addr().String(), nil)
	if res.Result != "hit" {
		t.Fatalf("CONNECT 隧道应命中 got=%s log=%s", res.Result, res.Log)
	}

	// 裸 host:port（无 scheme）→ 显式报错，禁止静默直连
	res = e.RunSink(context.Background(), spec, target, "127.0.0.1:1", nil)
	if res.Result != "error" || !strings.Contains(res.Log, "代理地址无效") {
		t.Fatalf("裸代理地址应显式报错 got=%s log=%s", res.Result, res.Log)
	}

	// 不支持的 scheme → 显式报错
	res = e.RunSink(context.Background(), spec, target, "ftp://127.0.0.1:1", nil)
	if res.Result != "error" || !strings.Contains(res.Log, "不支持的代理协议") {
		t.Fatalf("未知 scheme 应显式报错 got=%s log=%s", res.Result, res.Log)
	}
}
