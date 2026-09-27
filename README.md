# 本地信封加密与主密钥轮换组件（Go）

纯 Go 标准库实现（无第三方依赖）的**本地信封加密（Envelope Encryption）**组件：

- 主密钥多版本管理与**轮换**：新数据用当前版本加密，旧密文永远能按其写入版本解开；
- **按租户隔离**的加解密：跨租户读/写一律拒绝，且拒绝原因可区分；
- 并发加解密与轮换同时发生时状态一致；写入走原子落盘，不留半成品密文；
- 密钥材料**绝不明文落盘、不进日志**。

## 目录结构

| 文件 | 职责 |
| --- | --- |
| `envelope.go` | `Service`：租户访问控制、信封加解密编排、写入策略与冲突重试 |
| `keyring.go` | `Keyring`：主密钥多版本、轮换、KEK 包装、原子持久化 |
| `storage.go` | `Storage`：密文记录文件存储、per-record 锁、路径穿越校验 |
| `crypto.go` | AES-256-GCM 封包、随机密钥生成、PBKDF2-HMAC-SHA256（KEK 派生） |
| `util.go` | `writeFileAtomic`（临时文件 + fsync + rename）、时间辅助 |
| `errors.go` | 哨兵错误与携带结构化上下文的错误类型 |

## 密钥层次与信封结构

```
passphrase ──PBKDF2-HMAC-SHA256(salt, 200_000)──▶ KEK（主密钥加密密钥，仅存在于内存）
主密钥 MK[v]（32B 随机，AES-256） ──KEK/AES-GCM 包装──▶ 落盘的密态主密钥
每条消息随机 DEK（32B）            ──MK[当前版本]/AES-GCM 包装──▶ wrapped_dek（随密文记录存放）
明文                               ──DEK/AES-GCM，AAD 绑定租户/记录/版本──▶ ciphertext
```

磁盘布局（目录权限 `0700`、文件权限 `0600`）：

```
<data-dir>/
├── keyring.json            # 只含 KDF 公开参数(salt/迭代数) + 各版本密态主密钥
└── records/
    └── <recordID>          # 一条密文记录的 JSON
```

`keyring.json` 中没有明文主密钥，也没有口令；`records/` 中没有明文数据、没有明文 DEK。
测试 `TestKeyringFileContainsNoPlaintextMaterial` / `TestCiphertextFileContainsNoPlaintextOrDEK`
会直接扫描落盘字节做断言。

## 密钥版本与轮换规则

1. `CreateKeyring` 初始化即生成 **v1** 主密钥，`current_version = 1`。
2. `RotateKey()` 生成一把全新随机主密钥，分配单调递增的新版本号并把
   `current_version` 推进到新版本；**所有历史版本原样保留**。
3. **新写入**始终使用当前版本：版本号与 DEK 包装在 Keyring 的同一把读锁内确定，
   与并发轮换线性一致——一次加密要么整段使用旧版本、要么整段使用新版本。
4. **解密**只相信密文记录里自带的 `key_version`，用对应版本解包 DEK：
   - 轮换不重写、不迁移任何历史密文，旧密文继续由旧版本解开；
   - 密文引用的版本在密钥环中不存在时，返回
     `*KeyVersionError`（`errors.Is(err, ErrKeyVersionNotFound)` 成立，
     错误中带缺失版本号、租户、记录 ID），**绝不静默降级**到其它版本尝试解密。
5. 轮换的“生成版本 → 推进指针 → 落盘”在同一把写锁内完成并原子写文件；
   落盘失败会回滚内存状态，不会出现指针已推进但未持久化的中间态。

## 租户访问控制规则

密文记录内固化 `tenant_id`（属主），并通过 GCM 的 AAD
`envelope:data:...:tenant=<t>:record=<id>:key_version=<v>` 与
`envelope:dek:...` 把租户、记录 ID、密钥版本同时绑定进认证标签：

- **解密**：调用方 `tenantID` 与记录属主不一致 → 返回
  `*TenantAccessError`（`errors.Is(err, ErrTenantMismatch)`），
  字段区分请求方、属主、记录 ID 与操作类型；
- **加密（覆盖已存在记录）**：非属主写入 → 同样返回 `ErrTenantMismatch`，
  原属主数据不变；
- **加密（新建）**：记录 ID 已被别的租户占用时，无论并发与否，
  非属主都会得到 `ErrTenantMismatch`（属主本人得到 `ErrRecordAlreadyExists`）；
  “检查—加密—落盘”之间的竞争由存储层原子创建裁决，组件会重读记录、
  重新做属主判定并重试，不会借重试窗口写进别人的数据；
- 密文被改名/挪用到其它租户或记录语境时，AAD 不匹配，解密返回
  `ErrInvalidCiphertext`。

## 错误原因区分（调用方视角）

| 场景 | 判断方式 |
| --- | --- |
| 引用的主密钥版本不存在 | `errors.Is(err, envelope.ErrKeyVersionNotFound)`，并可 `errors.As` 到 `*envelope.KeyVersionError` 取版本号 |
| 跨租户读 / 写 | `errors.Is(err, envelope.ErrTenantMismatch)`，并可 `errors.As` 到 `*envelope.TenantAccessError` 取双方租户与操作 |
| 记录不存在 | `errors.Is(err, envelope.ErrRecordNotFound)` |
| 新建时记录已存在 | `errors.Is(err, envelope.ErrRecordAlreadyExists)` |
| 密文损坏 / 被篡改 / AAD 不符 | `errors.Is(err, envelope.ErrInvalidCiphertext)` |
| 入参非法（空租户、非法记录 ID 等） | `errors.Is(err, envelope.ErrInvalidArgument)` |
| 密钥环口令错误 | `errors.Is(err, envelope.ErrInvalidPassphrase)` |

记录 ID 仅允许 `[A-Za-z0-9_-][A-Za-z0-9_.-]{0,127}`，防止路径穿越。

## 并发一致性与崩溃安全

- **Keyring**：`sync.RWMutex`，加解密持读锁（可并行），轮换持写锁（互斥）。
- **Storage**：per-record 分桶互斥锁串行化同记录写入；不同记录互不阻塞。
- **原子落盘**：每次写入先写同目录临时文件 → `fsync` → `rename` 替换。
  目标文件任何时刻要么是完整旧内容、要么是完整新内容；写失败只残留临时文件，
  不会产生半成品密文，后续解密不受影响。
- 进程重启后用同一口令 `OpenKeyring` 即可解包全部保留版本，历史密文照常解密。

> 锁为单进程内锁；文件层原子性在进程崩溃/异常退出后依然成立。多进程同时写
> 同一数据目录不在本组件的支持范围内。

日志通过 `log/slog` 输出结构化字段，所有加解密/轮换/拒绝事件都携带
`key_version` 与 `basis`（判定依据）等字段；密钥材料、明文、口令不会出现在日志里。
可向 `CreateKeyring / OpenKeyring / NewService` 传入自定义 `*slog.Logger`。

## 快速上手

```go
kr, _ := envelope.CreateKeyring("./data", "a-local-passphrase", logger)
st, _ := envelope.NewStorage("./data")
svc, _ := envelope.NewService(kr, st, logger)

// 属主加密（v1）
svc.Encrypt("tenant-a", "invoice-1", []byte("amount=100"), envelope.WritePolicyMustCreate)

// 轮换：之后新数据用新版本，旧密文仍可解
svc.RotateKey()

// 属主解密（自动按记录内版本选主密钥）
pt, rec, err := svc.Decrypt("tenant-a", "invoice-1")
```

## 本地验证

要求 Go 1.25+（开发环境为 Go 1.26）。无需联网、无第三方依赖。

```bash
# 全部单元测试（包含轮换后读旧数据、跨租户越权、并发读写+轮换、原子写等）
go test -v ./...

# 竞态检测（需要 cgo；并发测试全部以 -race 验证）
CGO_ENABLED=1 go test -race ./...

# 静态检查
go vet ./...

# 可运行示例（ExampleService，输出由 go test 自动比对）
go test -run Example -v ./...
```

重点测试与需求对应：

| 测试 | 覆盖点 |
| --- | --- |
| `TestRotateThenOldCiphertextStillDecryptsAndNewWritesUseNewVersion` | 轮换后旧密文可解、新密文用新版本 |
| `TestKeyringRotationRetainsOldVersions` / `TestConcurrentRotationSurvivesRestart` | 版本保留、轮换持久化、重启一致性 |
| `TestKeyringUnwrapMissingVersionIsDistinguishable` / `TestDecryptReferencingMissingKeyVersionIsDistinguishable` | 缺失版本错误可区分、不降级 |
| `TestCrossTenantDecryptDeniedWithDistinguishableReason` / `TestCrossTenantWriteOverwriteDenied` / `TestConcurrentCreateSameIDDifferentTenantsOnlyOwnerWins` | 跨租户读/写/抢建越权拒绝且原因可区分 |
| `TestConcurrentEncryptDecryptAndRotate` | 大量 goroutine 并发加密/解密/轮换，校验无损坏、无版本错乱（-race） |
| `TestConcurrentWritesSameRecordNeverCorrupt` | 同记录并发覆盖写，读到的永远是某一次完整写入（-race） |
| `TestAtomicWriteLeavesNoHalfWrittenFile` | 模拟写入中途崩溃残留临时文件，正式密文不受影响 |
| `TestTamperedCiphertextRejected` | 篡改密文后 GCM 认证失败 |
| `TestKeyringFileContainsNoPlaintextMaterial` / `TestCiphertextFileContainsNoPlaintextOrDEK` | 落盘内容不含明文密钥/数据 |

`go test -v` 的输出中，相关用例还会通过 `slog:` 行与 `t.Logf` 打印
实际使用的 `key_version` 与判定依据（`basis`）。

## 安全说明与边界

- 口令是本地 KEK 的唯一来源，应通过安全渠道注入（环境变量/密钥管理），不要硬编码；
  PBKDF2 迭代数默认 200,000，可按需要调整。
- 本组件解决“本地静态加密 + 版本化主密钥轮换 + 租户隔离 + 并发一致性”，
  不包含口令找回、多实例共享存储、已删除版本的密文迁移/重新加密（re-encryption）。
  一旦某个主密钥版本被物理移除，引用它的密文将稳定地收到
  `ErrKeyVersionNotFound`。
