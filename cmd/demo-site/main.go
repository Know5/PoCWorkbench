// demo-site 起一个本地演示站（HTTP :18080 / TCP :18081），带六类"故意留洞"
// 的页面，供用 PoCWorkbench GUI 手动验证各类 PoC 的真实效果。
package main

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

func main() {
	mux := http.NewServeMux()

	// 洞 1：SQL 时间盲注——注入 SLEEP 才延迟，响应内容与正常请求完全一致
	mux.HandleFunc("/sqli-time", func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(strings.ToLower(r.URL.RawQuery), "sleep") {
			time.Sleep(1200 * time.Millisecond)
		}
		fmt.Fprint(w, "query ok")
	})

	// 洞 2：串联提取——GET 取 reportId，POST 用它命中特权渲染
	mux.HandleFunc("/api/list", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"code":0,"data":{"reportId":"R9X7"},"msg":"ok"}`)
	})
	mux.HandleFunc("/api/exec", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("rid") == "R9X7" {
			fmt.Fprint(w, "render: uid=0(root) mode=privileged")
			return
		}
		fmt.Fprintf(w, "report %s not found", r.URL.Query().Get("rid"))
	})

	// 洞 3：敏感信息泄露（内容匹配）
	mux.HandleFunc("/leak", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"admin_password":"P@ssw0rd2026","hint":"internal use only"}`)
	})

	// 洞 4：手机号形态（正则匹配）
	mux.HandleFunc("/users", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"contacts":[{"phone":"13812345678"},{"phone":"13987654321"}]}`)
	})

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "welcome to demo corp portal")
	})

	// TCP 演示服务：发 "@DEMO@ probe" 回未授权 banner；其他输入回普通 banner
	ln, err := net.Listen("tcp", ":18081")
	if err != nil {
		fmt.Println("TCP 监听失败:", err)
		os.Exit(1)
	}
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

	fmt.Println("演示站已启动：")
	fmt.Println("  HTTP 目标填: http://127.0.0.1:18080")
	fmt.Println("  TCP  目标填: 127.0.0.1:18081")
	fmt.Println("洞口清单：")
	fmt.Println("  /sqli-time?id=1           SQL 时间盲注（注入 AND SLEEP(1) 延迟 1.2s）")
	fmt.Println("  /api/list + /api/exec      串联提取（reportId=R9X7 → 特权渲染）")
	fmt.Println("  /leak                      敏感信息泄露（admin_password）")
	fmt.Println("  /users                     手机号形态（13812345678）")
	fmt.Println("  TCP @DEMO@ probe           未授权模式 banner（unauth-mode）")
	fmt.Println("反例：根路径 / 为正常页面，用于验证不误报")
	if err := http.ListenAndServe(":18080", mux); err != nil {
		fmt.Println("HTTP 监听失败:", err)
		os.Exit(1)
	}
}
