# 破壳 PoCShell (PoCWorkbench)

桌面端 PoC 管理与验证工作台。把散落的 xray 模板、手写 PoC 收进一个带全文检索的本地库，用自研引擎对授权目标做安全验证——单文件 Windows 应用，开箱即用。

> 当前版本：v1.0.0

## 功能特性

### PoC 库管理
- **xray 模板导入**：粘贴 YAML 自动转换为 PWF 格式，冷门字段（set/output 等）不静默丢弃，逐条进警告列表
- **三关校验**：严格 schema → 表达式编译 → 总表达式 rule 引用检查，坏 PoC 进不了库
- **全文检索**：SQLite FTS trigram（中文 ≥3 字词）+ LIKE 回退（短词），按名称/CVE/标签/描述/厂商检索
- **厂商/产品字典治理**：别名归并、输入时自动补全（包含匹配、不分大小写）、PoC 一键指派
- **生命周期**：归档/恢复/删除（仅限已归档）、单条导出为 YAML、整库备份（VACUUM INTO）

### 验证引擎（自研，无外部依赖）
- **双 transport**：HTTP（关闭重定向跟随、TLS 跳过校验对齐安全测试惯例）/ TCP（多 input 收发）
- **表达式求值**：[expr-lang](https://github.com/expr-lang/expr) + xray 风格函数注册表，规则惰性求值 + 短路（`r0()` 为假时 `r1()` 不发请求）
- **时间盲注**：`response.elapsed_ms` 暴露每条规则的真实网络耗时，配合基线对照规则做阈值判定：

```yaml
transport: http
rules:
    base:
        request: {method: GET, path: /index.php?id=1}
        expression: response.status == 200 && response.elapsed_ms < 3000
    delay5:
        request: {method: GET, path: "/index.php?id=1 AND IF(1,SLEEP(5),0)"}
        expression: response.elapsed_ms >= 4000
expression: base() && delay5()
```

- **代理支持**：HTTP transport 支持 http/https/socks5；TCP transport 支持 socks5 与 http CONNECT 隧道（挂 Burp 调试）；非法代理地址显式报错，绝不静默直连
- **资源防护**：全局并发=1、单次运行 60s 硬超时、响应读上限 10MB、TCP 写超时 + ctx 看门狗（tarpit 目标不会卡死引擎）、正则 RE2 线性时间免疫 ReDoS、YAML 深度预扫拒绝恶意嵌套

### 桌面体验
- Wails v2 单文件应用，无边框自绘窗口，深浅色主题
- 批量测试事件流（log/result/progress/done），可中途取消，结果落库
- 启动失败持久横幅（数据库锁、磁盘异常等不再静默）
- 测试日志自动脱敏：`password/token/secret/api_key` 值替换为 `***`

## 安全属性

- 无外部进程调用：引擎能力面仅 HTTP/TCP 收发 + 布尔判断
- 每次执行需显式勾选测试授权确认
- 全部 SQL 参数化，FTS/LIKE 输入转义
- 数据落盘于 `%APPDATA%\PoCWorkbench\pocwb.db`（WAL 模式），卸载即清

## 构建

依赖：Go ≥ 1.25、Node.js（前端 Vite 构建）

```bat
build.bat          # 默认 v1.0.0
build.bat v1.0.1   # 指定版本号（注入到设置页展示）
```

产物为根目录 `PoCWorkbench.exe`（约 17MB，WebView2 运行时为系统组件，Win11 内置）。

## 目录结构

```
├─ main.go               # Wails 入口
├─ app/                  # 绑定层（前端可见的全部方法）
├─ internal/
│  ├─ engine/            # 执行引擎：HTTP/TCP 收发、超时、代理、表达式求值
│  ├─ pwf/               # PWF spec 三关校验、表达式变换、规范化哈希
│  ├─ convert/           # xray → PWF 转换器
│  ├─ exprfn/            # 表达式函数注册表（校验与引擎共用，保证同构）
│  ├─ store/             # SQLite 持久层（WAL、FTS、事务）
│  └─ model/             # 数据模型
└─ frontend/             # React + Vite + Tailwind
```

## 免责声明

本工具仅用于**已授权**的安全测试与漏洞验证。对未授权目标使用造成的任何后果由使用者自行承担。
