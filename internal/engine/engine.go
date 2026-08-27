// Package engine 是自研 PWF 执行引擎：HTTP/TCP 收发 + expr-lang 表达式求值。
//
// 安全属性（方案 §3.6）：
//   - 无外部进程；能力面仅 HTTP/TCP 收发与布尔判断
//   - 全局并发=1 执行队列；单次硬超时（默认 60s）
//   - HTTP 关闭重定向跟随；响应读上限 10MB；TLS 默认跳过校验（对齐 xray/nuclei 惯例）
//   - 正则走 Go regexp（RE2 语义），线性时间，免疫 ReDoS
package engine

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	netproxy "golang.org/x/net/proxy"

	"github.com/expr-lang/expr"
	"github.com/expr-lang/expr/vm"

	"pocworkbench/internal/exprfn"
	"pocworkbench/internal/model"
	"pocworkbench/internal/pwf"
)

const maxBodyBytes = 10 << 20 // 10MB 响应读上限

// Options 引擎配置。
type Options struct {
	RunTimeout time.Duration // 单次运行硬超时，默认 60s
	MaxConc    int           // 全局并发，默认 1
}

type Engine struct {
	opts     Options
	slots    chan struct{}
	mu       sync.Mutex
	programs map[string]*vm.Program
	clients  map[string]*http.Client // key: ""=直连 或代理 URL
}

func New(opts Options) *Engine {
	if opts.RunTimeout <= 0 {
		opts.RunTimeout = 60 * time.Second
	}
	if opts.MaxConc <= 0 {
		opts.MaxConc = 1
	}
	return &Engine{
		opts:     opts,
		slots:    make(chan struct{}, opts.MaxConc),
		programs: map[string]*vm.Program{},
		clients:  map[string]*http.Client{},
	}
}

// Response 注入表达式的响应环境。
type Response struct {
	Status      int
	Headers     map[string]string
	Body        []byte
	ContentType string
	Raw         []byte
	// ElapsedMs 本条规则的响应耗时（毫秒），供时间盲注类表达式使用。
	// http：请求写完 → 首个响应字节（不含 DNS/建连/下载）；tcp：含拨号与读等待的全程。
	ElapsedMs int64
}

// compileOptions 委托共享注册表（pwf 校验与引擎求值必须同构）。
func compileOptions() []expr.Option {
	return exprfn.Options()
}

// httpClientFor 按代理地址返回客户端（直连/各代理各一个，复用连接池）。
// 代理地址须带 scheme 且 host 非空，否则报错——禁止裸 host:port 之类在请求期才炸出晦涩错误的形态。
func (e *Engine) httpClientFor(proxyURL string) (*http.Client, error) {
	if strings.TrimSpace(proxyURL) == "" {
		return directClient, nil
	}
	if u, err := url.Parse(proxyURL); err != nil || u.Host == "" {
		return nil, fmt.Errorf("代理地址无效: %q（示例 http://127.0.0.1:8080）", proxyURL)
	} else if s := strings.ToLower(u.Scheme); s != "http" && s != "https" && s != "socks5" && s != "socks5h" {
		return nil, fmt.Errorf("不支持的代理协议 %q（支持 http/https/socks5）", u.Scheme)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if c, ok := e.clients[proxyURL]; ok {
		return c, nil
	}
	u, _ := url.Parse(proxyURL) // 上面已校验
	c := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse },
		Transport:     newHTTPTransport(u),
	}
	e.clients[proxyURL] = c
	return c, nil
}

// newHTTPTransport 统一配置拨号/TLS 握手/空闲连接：DNS 卡死与握手悬挂先行失败，
// 不必等 runCtx 60s 硬超时兜底；空闲连接限时关闭，批量场景不堆积半开连接。
func newHTTPTransport(proxyURL *url.URL) *http.Transport {
	t := &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true}, // 对齐安全测试惯例
		DialContext:         (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		TLSHandshakeTimeout: 10 * time.Second,
		IdleConnTimeout:     90 * time.Second,
		MaxIdleConnsPerHost: 8,
	}
	if proxyURL != nil {
		t.Proxy = http.ProxyURL(proxyURL)
	}
	return t
}

var directClient = &http.Client{
	CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse },
	Transport:     newHTTPTransport(nil),
}

// compileCached 带缓存的编译。
func (e *Engine) compileCached(src string, extra ...expr.Option) (*vm.Program, error) {
	opts := append(compileOptions(), extra...)
	e.mu.Lock()
	defer e.mu.Unlock()
	if p, ok := e.programs[src]; ok && len(extra) == 0 {
		return p, nil
	}
	p, err := expr.Compile(src, opts...)
	if err != nil {
		return nil, err
	}
	if len(extra) == 0 {
		e.programs[src] = p
	}
	return p, nil
}

// ---- 运行结果 ----

type RunResult struct {
	Result string // hit|miss|error|timeout|cancelled
	Log    string
}

type ruleState struct {
	done  bool
	value bool
	err   error
}

// Run 执行（无日志回调）。
func (e *Engine) Run(ctx context.Context, spec *model.Spec, target string) RunResult {
	return e.RunSink(ctx, spec, target, "", nil)
}

// RunSink 执行一个 PWF spec 对 target；每行日志同时回调 sink（可为 nil）。
func (e *Engine) RunSink(ctx context.Context, spec *model.Spec, target, proxy string, sink func(string)) RunResult {
	select {
	case e.slots <- struct{}{}:
		defer func() { <-e.slots }()
	case <-ctx.Done():
		return RunResult{Result: "cancelled"}
	}

	runCtx, cancel := context.WithTimeout(ctx, e.opts.RunTimeout)
	defer cancel()

	started := time.Now()
	var logBuf strings.Builder
	logf := func(format string, args ...any) {
		line := fmt.Sprintf(format+"\n", args...)
		logBuf.WriteString(line)
		if sink != nil {
			sink(strings.TrimRight(line, "\n"))
		}
	}

	// 按 transport 校验目标（http 须 http/https URL；tcp 须 host:port）
	if err := ValidateTarget(spec.Transport, target); err != nil {
		return RunResult{Result: "error", Log: err.Error()}
	}

	states := map[string]*ruleState{}
	var mu sync.Mutex
	evalRule := func(name string) (bool, error) {
		mu.Lock()
		st, ok := states[name]
		if !ok {
			st = &ruleState{}
			states[name] = st
			mu.Unlock()
			rule := spec.Rules[name]
			val, rlog, rerr := e.execRule(runCtx, spec.Transport, name, rule, target, proxy, started)
			logBuf.WriteString(rlog)
			mu.Lock()
			st.done = true
			if rerr != nil {
				st.err = rerr
			} else {
				st.value = val
			}
			mu.Unlock()
			return val, rerr
		}
		mu.Unlock()
		if st.err != nil {
			return false, st.err
		}
		return st.value, nil
	}

	// 注册规则函数：惰性求值 + 缓存 + 短路
	opts := make([]expr.Option, 0, len(spec.Rules))
	for name := range spec.Rules {
		nm := name
		opts = append(opts, expr.Function(nm, func(...any) (any, error) {
			v, err := evalRule(nm)
			return v, err
		}))
	}
	finalSrc := pwf.TransformExpression(spec.Expression)
	program, err := expr.Compile(finalSrc, append(opts, expr.AsBool())...)
	if err != nil {
		return RunResult{Result: "error", Log: logBuf.String() + "总表达式编译失败: " + err.Error()}
	}

	env := map[string]any{}
	out, err := expr.Run(program, env)
	if err != nil {
		if runCtx.Err() == context.DeadlineExceeded || ctx.Err() == context.Canceled {
			result := classifyCtx(ctx, runCtx)
			return RunResult{Result: result, Log: logBuf.String()}
		}
		return RunResult{Result: "error", Log: logBuf.String() + "求值失败: " + err.Error()}
	}
	hit, _ := out.(bool)
	result := "miss"
	if hit {
		result = "hit"
	}
	logf("[final] expression=%s => %v (%s)", finalSrc, hit, time.Since(started).Round(time.Millisecond))
	return RunResult{Result: result, Log: logBuf.String()}
}

func classifyCtx(parent, run context.Context) string {
	if parent.Err() == context.Canceled {
		return "cancelled"
	}
	if run.Err() == context.DeadlineExceeded {
		return "timeout"
	}
	return "error"
}

// ValidateTarget 按 transport 校验目标格式：http 须 http/https URL；tcp 须 host:port。
// 引擎运行时与批量预筛（checkTargetFormat）共用，两端规则天然一致。
func ValidateTarget(transport, target string) error {
	if transport == "http" {
		u, err := url.Parse(target)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return fmt.Errorf("目标 URL 非法（须为 http/https 且 host 非空）")
		}
		return nil
	}
	t := target
	if i := strings.Index(t, "://"); i >= 0 {
		t = t[i+3:]
	}
	host, _, err := net.SplitHostPort(t)
	if err != nil || host == "" {
		return fmt.Errorf("TCP 目标非法（须为 host:port）")
	}
	return nil
}

func (e *Engine) execRule(ctx context.Context, transport, name string, rule model.Rule, target, proxy string, started time.Time) (bool, string, error) {
	var resp *Response
	var err error
	switch transport {
	case "http":
		resp, err = e.execHTTP(ctx, rule.Request, target, proxy)
	default:
		resp, err = e.execTCP(ctx, rule.Request, target, proxy)
	}
	if err != nil {
		return false, fmt.Sprintf("[%s] 执行失败: %v\n", name, err), err
	}

	src := pwf.TransformExpression(rule.Expression)
	program, cerr := e.compileCached(src)
	if cerr != nil {
		return false, "", fmt.Errorf("rule %s 表达式编译失败: %w", name, cerr)
	}
	env := map[string]any{"response": respMap(resp)}
	out, verr := expr.Run(program, env)
	if verr != nil {
		return false, "", fmt.Errorf("rule %s 求值失败: %w", name, verr)
	}
	val, _ := out.(bool)
	logLine := fmt.Sprintf("[%s] %s => %v (%s)\n", name, describeRequest(transport, rule.Request, target), val, time.Since(started).Round(time.Millisecond))
	logLine += describeResponse(transport, resp)
	return val, logLine, nil
}

func describeRequest(transport string, req model.Request, target string) string {
	if transport == "http" {
		return fmt.Sprintf("%s %s%s", req.Method, strings.TrimRight(target, "/"), req.Path)
	}
	return fmt.Sprintf("tcp %s inputs=%d", target, len(req.Inputs))
}

// respMap 把 Response 转为与 exprfn.EnvShape 同构的 map（编译/运行类型一致）。
func respMap(r *Response) map[string]any {
	return map[string]any{
		"status":       r.Status,
		"headers":      r.Headers,
		"body":         r.Body,
		"content_type": r.ContentType,
		"raw":          r.Raw,
		"elapsed_ms":   r.ElapsedMs,
	}
}

func describeResponse(transport string, r *Response) string {
	var b strings.Builder
	if transport == "http" {
		fmt.Fprintf(&b, "    status=%d content_type=%s body_len=%d elapsed=%dms\n", r.Status, r.ContentType, len(r.Body), r.ElapsedMs)
		b.WriteString("    body_head=" + head(r.Body, 512) + "\n")
	} else {
		fmt.Fprintf(&b, "    raw_len=%d elapsed=%dms\n", len(r.Raw), r.ElapsedMs)
		b.WriteString("    raw_head=" + head(r.Raw, 512) + "\n")
	}
	return b.String()
}

func head(b []byte, n int) string {
	s := string(b)
	if len(s) > n {
		cut := n // 回退到 UTF-8 rune 边界，避免日志头部尾部乱码
		for cut > 0 && !utf8.RuneStart(s[cut]) {
			cut--
		}
		s = s[:cut] + "...(截断)"
	}
	return strings.ReplaceAll(s, "\n", "\\n")
}

// ---- HTTP ----

func (e *Engine) execHTTP(ctx context.Context, req model.Request, target, proxy string) (*Response, error) {
	fullURL := strings.TrimRight(target, "/") + req.Path
	bodyReader := strings.NewReader(req.Body)
	httpReq, err := http.NewRequestWithContext(ctx, orDefault(req.Method, "GET"), fullURL, bodyReader)
	if err != nil {
		return nil, err
	}
	for k, v := range req.Headers {
		httpReq.Header.Set(k, v)
	}
	started := time.Now()
	client, err := e.httpClientFor(proxy)
	if err != nil {
		return nil, err
	}
	// 计时口径：请求写完 → 首个响应字节。时间盲注的 SLEEP(N) 发生在服务端生成响应阶段，
	// 该区间不含 DNS/建连（同 Run 内首条规则不再独自承担握手成本）与下载耗时
	var wroteReqAt, firstByteAt time.Time
	httpReq = httpReq.WithContext(httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
		WroteRequest:         func(httptrace.WroteRequestInfo) { wroteReqAt = time.Now() },
		GotFirstResponseByte: func() { firstByteAt = time.Now() },
	}))
	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	elapsed := time.Since(started) // 兜底：trace 事件缺失时退化为全耗时
	if !wroteReqAt.IsZero() && !firstByteAt.IsZero() && firstByteAt.After(wroteReqAt) {
		elapsed = firstByteAt.Sub(wroteReqAt)
	}
	if err != nil && err != io.EOF {
		return nil, err
	}
	// response.raw：HTTP 下与 body 同源（xray 语义中 http 场景 raw≈响应体）；
	// 此前 LimitReader(0) 使其恒为空，引用它的表达式会静默判错。
	raw := body

	hdrs := map[string]string{}
	for k := range resp.Header {
		hdrs[strings.ToLower(k)] = resp.Header.Get(k)
	}
	ct := ""
	if v, ok := hdrs["content-type"]; ok {
		ct = v
	}
	return &Response{
		Status:      resp.StatusCode,
		Headers:     hdrs,
		Body:        body,
		ContentType: ct,
		Raw:         raw,
		ElapsedMs:   elapsed.Milliseconds(),
	}, nil
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

// ---- TCP ----
// httpConnectDialer 经 HTTP 代理 CONNECT 隧道建立 TCP 连接（挂 Burp 等调试代理）。
type httpConnectDialer struct {
	proxyHost string
	basicAuth string // Proxy-Authorization 值（"Basic xxx"），可空
}

func (c *httpConnectDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if network != "tcp" {
		return nil, fmt.Errorf("CONNECT 隧道仅支持 tcp，got %q", network)
	}
	d := net.Dialer{Timeout: 5 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", c.proxyHost)
	if err != nil {
		return nil, fmt.Errorf("连接代理 %s 失败: %w", c.proxyHost, err)
	}
	req := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Opaque: address},
		Host:   address,
		Header: make(http.Header),
	}
	if c.basicAuth != "" {
		req.Header.Set("Proxy-Authorization", c.basicAuth)
	}
	if err := req.Write(conn); err != nil {
		conn.Close()
		return nil, fmt.Errorf("发送 CONNECT 失败: %w", err)
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("读取代理响应失败: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		conn.Close()
		resp.Body.Close()
		return nil, fmt.Errorf("代理建立隧道失败: %s", resp.Status)
	}
	// 隧道建立后代理不应再发数据；缓冲区有残留说明对端行为异常，宁断勿串
	if br.Buffered() > 0 {
		conn.Close()
		return nil, fmt.Errorf("代理在隧道建立前发送了异常数据")
	}
	return conn, nil
}

// proxyBasicAuth 由代理 URL 的 userinfo 生成 Proxy-Authorization 值。
func proxyBasicAuth(u *url.Userinfo) string {
	if u == nil {
		return ""
	}
	pw, _ := u.Password()
	req := &http.Request{Header: make(http.Header)}
	req.SetBasicAuth(u.Username(), pw)
	return req.Header.Get("Authorization")
}

type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

func (e *Engine) execTCP(ctx context.Context, req model.Request, target, proxy string) (*Response, error) {
	started := time.Now()
	hostPort := hostPortOf(target)
	var d net.Dialer
	var dialer Dialer = &d
	if purl := strings.TrimSpace(proxy); purl != "" {
		// 用户显式配置代理时，TCP 流量必须经代理；不支持的一律显式报错，禁止静默直连
		pu, err := url.Parse(purl)
		if err != nil || pu.Host == "" {
			return nil, fmt.Errorf("TCP 代理地址无效: %q（支持 socks5:// 与 http://，须带 scheme）", purl)
		}
		switch strings.ToLower(pu.Scheme) {
		case "socks5", "socks5h":
			var auth *netproxy.Auth
			if pu.User != nil {
				pw, _ := pu.User.Password()
				auth = &netproxy.Auth{User: pu.User.Username(), Password: pw}
			}
			pd, perr := netproxy.SOCKS5("tcp", pu.Host, auth, netproxy.Direct)
			if perr != nil {
				return nil, perr
			}
			cd, ok := pd.(netproxy.ContextDialer)
			if !ok {
				return nil, fmt.Errorf("SOCKS5 拨号器不支持 context 取消")
			}
			dialer = cd
		case "http", "https":
			// http(s):// 代理走 CONNECT 隧道（挂 Burp 等调试代理的常规形态）
			dialer = &httpConnectDialer{proxyHost: pu.Host, basicAuth: proxyBasicAuth(pu.User)}
		default:
			return nil, fmt.Errorf("TCP 传输不支持的代理协议 %q（支持 socks5:// 与 http://）", pu.Scheme)
		}
	}
	conn, err := dialer.DialContext(ctx, "tcp", hostPort)
	if err != nil {
		return nil, err
	}
	// 所有返回路径（成功/写失败/取消/读满提前返回）都必须关闭连接，否则批量测试会泄漏 socket
	defer conn.Close()
	readTimeout := time.Duration(req.ReadTimeout) * time.Second
	if readTimeout <= 0 {
		readTimeout = 3 * time.Second
	}

	// 看门狗：ctx 取消/超时后强制解除所有阻塞中的读写（含卡死的 Write syscall）
	watchDone := make(chan struct{})
	defer close(watchDone)
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.SetDeadline(time.Now())
		case <-watchDone:
		}
	}()

	var raw []byte
	buf := make([]byte, 32*1024)
	for _, input := range req.Inputs {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if input.Data != "" {
			// 写超时与读一致：对端不读时 Write 不能无限阻塞
			_ = conn.SetWriteDeadline(time.Now().Add(readTimeout))
			if _, err := conn.Write([]byte(input.Data)); err != nil {
				return nil, err
			}
		}
		deadline := time.Now().Add(readTimeout)
		_ = conn.SetReadDeadline(deadline)
		for {
			n, err := conn.Read(buf)
			if n > 0 {
				raw = append(raw, buf[:n]...)
			}
			if len(raw) > maxBodyBytes {
				return &Response{Raw: raw, ElapsedMs: time.Since(started).Milliseconds()}, nil
			}
			if err != nil {
				break // 超时或对端关闭都结束本轮读取
			}
		}
	}
	return &Response{Raw: raw, ElapsedMs: time.Since(started).Milliseconds()}, nil
}

func hostPortOf(target string) string {
	t := target
	if i := strings.Index(t, "://"); i >= 0 {
		t = t[i+3:]
	}
	if i := strings.Index(t, "/"); i >= 0 {
		t = t[:i]
	}
	if !strings.Contains(t, ":") {
		t += ":80"
	}
	return t
}
