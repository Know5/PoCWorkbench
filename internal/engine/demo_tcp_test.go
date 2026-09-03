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

// 演示 5：TCP 协议验证——发送握手后对端回带版本号的 banner。
func TestDemoTCPBanner(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				br := bufio.NewReader(c)
				line, _ := br.ReadString('\n')
				if strings.HasPrefix(line, "@DEMO@") {
					c.Write([]byte("DEMO-SVC 2.3.1 unauth-mode\n"))
				} else {
					c.Write([]byte("DEMO-SVC 2.3.1\n"))
				}
			}(conn)
		}
	}()

	e := New(Options{RunTimeout: 10 * time.Second})
	spec := &model.Spec{
		Transport: "tcp",
		Rules: map[string]model.Rule{
			"r0": {
				Request: model.Request{
					Inputs:      []model.TCPInput{{Data: "@DEMO@ probe\n"}},
					ReadTimeout: 3,
				},
				Expression: `response.raw.bcontains(b'unauth-mode')`,
			},
		},
		Expression: "r0()",
	}
	res := e.RunSink(context.Background(), spec, "tcp://"+ln.Addr().String(), "", nil)
	if res.Result != "hit" {
		t.Fatalf("TCP banner 应命中 got=%s log=%s", res.Result, res.Log)
	}

	// 反例：探测串不带 @DEMO@ → 普通 banner，不含 unauth-mode
	spec2 := &model.Spec{
		Transport: "tcp",
		Rules: map[string]model.Rule{
			"r0": {
				Request: model.Request{
					Inputs:      []model.TCPInput{{Data: "hello\n"}},
					ReadTimeout: 3,
				},
				Expression: `response.raw.bcontains(b'unauth-mode')`,
			},
		},
		Expression: "r0()",
	}
	res2 := e.RunSink(context.Background(), spec2, "tcp://"+ln.Addr().String(), "", nil)
	if res2.Result != "miss" {
		t.Fatalf("普通 banner 不应命中 got=%s log=%s", res2.Result, res2.Log)
	}
}
