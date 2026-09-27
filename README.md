# 本地信封加密与主密钥轮换组件（Go）

一个纯本地、无外部 KMS 依赖的信封加密（envelope encryption）组件，支持：

- 主密钥**多版本管理与轮换**：新数据始终用当前版本加密；轮换后历史密文凭保留的旧版本密钥仍可解密；
- **按租户隔离**的加解密，跨租户读写被拒绝，且拒绝原因可被调用方精确区分；
- 并发加解密与轮换同时进行时状态一致，写入原子落盘、不留半成品；
- 密钥材料（根密钥、KEK、DEK）绝不出现在落盘内容或日志中。

## 1. 目录布局

```
<Dir>/
├── keys.json                       # 密钥环元数据：版本号、派生盐（非秘密）、租户清单
└── tenants/
    └── <tenant>/
        └── data/
            └── <id>.json           # 一条业务密文一个文件
```

`keys.json` 与每条记录都以 `0600/0700` 权限写入，并通过
“临时文件 → fsync → 原子改名/硬链接发布”落盘，崩溃不会留下半截 JSON。

## 2. 密钥版本与轮换规则

1. **密钥派生**：根密钥 `Config.RootSecret`（≥16 字节）只存在于进程内存。
   每个主密钥版本有独立随机盐 `salt`（非秘密，可落盘），KEK 由
   `HKDF-SHA256(rootSecret, salt, info="envelope-kek-v<版本号>")`
   派生为 32 字节 AES-256 密钥。根密钥本身永不落盘。
2. **信封结构**：每条消息随机生成一把一次性 32 字节 DEK，用 DEK（AES-256-GCM）
   加密业务明文；再用对应版本的 KEK（AES-256-GCM）包裹 DEK。落盘的只有
   “被包裹的 DEK + 密文 + nonce + 版本号”，没有任何明文密钥材料。
   包裹 DEK 时以版本号作为 GCM 的 AAD，防止篡改记录里的版本号诱导解密。
3. **版本号**：从 1 开始单调递增。`Encrypt` 永远使用**当前版本**；
   `Decrypt` 按密文记录里的版本号取对应 KEK。
4. **轮换（RotateKey）**：生成新随机盐与新版本、设为当前版本，
   **旧版本全部保留**。因此：
   - 轮换前写入的密文（v1）轮换后仍按 v1 解密；
   - 轮换后新写入的密文使用新版本；
   - 不做、也不需要后台批量重加密（可作为后续扩展）。
5. **引用缺失版本**：密文引用的版本在密钥环中不存在时，返回
   `ErrKeyVersionNotFound`（`errors.As` 可取 `*KeyVersionError` 拿到版本号），
   **绝不静默降级**到其它版本，也不包装成笼统错误。
6. **重启恢复**：进程重启后从 `keys.json` 恢复全部历史版本与当前版本，
   根密钥由调用方再次提供；历史密文照常可解。

## 3. 访问控制规则（按租户）

- 租户必须先 `RegisterTenant` 注册（名字允许 `[A-Za-z0-9._-]`，1~128 字符；
  同样的白名单用于数据 ID，并据此杜绝路径穿越）。
- 存储路径按租户隔离：`tenants/<tenant>/data/<id>.json`。
- 每次 `Encrypt/Decrypt` 都做判定，跨租户访问按发生方式给出**不同但可区分**的原因：
  1. 调用方租户未在注册表中 → `ErrTenantUnknown`（`*TenantUnknownError`）；
  2. 已注册租户 B 在自己的命名空间访问 A 的数据 ID：因路径物理隔离，
     文件不在 B 的目录下 → `ErrRecordNotFound`，B 连“A 是否有该数据”都无法探知；
  3. 若数据文件被人为挪动/误投放到 B 的目录（绕过路径隔离），则以
     **文件内 owner 头**为准，owner ≠ 调用方 → `ErrTenantDenied`
     （`*TenantDeniedError`，携带调用方与属主）。存储层与 Service 层各检查一次，
     构成双保险，绝不把别人的数据解出来。
- 重复写同一 ID 返回 `ErrRecordExists`（`*RecordExistsError`），不覆盖旧密文。

## 4. 错误速查（全部可用 errors.Is/As 区分）

| 哨兵错误 | 含义 | 详细结构体 |
| --- | --- | --- |
| `ErrKeyVersionNotFound` | 密文引用的主密钥版本不存在 | `*KeyVersionError{Version}` |
| `ErrTenantDenied` | 跨租户访问（已注册但非属主） | `*TenantDeniedError{CallerTenant, OwnerTenant}` |
| `ErrTenantUnknown` | 租户未注册 | `*TenantUnknownError{Tenant}` |
| `ErrRecordNotFound` | 数据 ID 不存在 | `*RecordNotFoundError{Tenant, ID}` |
| `ErrRecordExists` | 写入目标已存在，拒绝覆盖 | `*RecordExistsError{Tenant, ID}` |
| `ErrCiphertextCorrupt` | 密文损坏/被篡改/格式非法 | `*CorruptCiphertextError{Tenant, ID, Reason}` |
| `ErrInvalidArgument` | 入参非法 | `*InvalidArgumentError{Argument, Reason}` |
| `ErrKeyringEmpty` | 密钥环未初始化 | — |

## 5. 并发一致性模型

- `keyring` 的版本表、当前版本、租户表存放在 `atomic.Pointer[快照]` 指向的
  **不可变快照**中；轮换/注册采用 copy-on-write 整体替换。读路径（解密取 KEK）
  无锁，且与轮换并发时只会看到“轮换前”或“轮换后”其中一个完整快照，
  不会出现版本错乱。
- `Service` 上一把 `sync.RWMutex`：
  - `Encrypt`、`RotateKey`、`RegisterTenant` 持写锁，彼此串行；
  - `Decrypt` 持读锁，可与其它解密并发，并与写操作通过原子快照安全并发。
- 轮换在“新快照发布”前/后与 `keys.json` 落盘配对：若元数据落盘失败，
  内存立即回滚为磁盘态，避免“用新版本加密、重启后版本消失”。
- 记录发布采用同目录临时文件 + `link(2)` 原子硬链接：目标已存在则
  `EEXIST → ErrRecordExists`，绝不覆盖；写入中途失败只留下被清理的临时文件，
  正式路径上永远不存在半成品密文。

## 6. 使用示例

```go
svc, err := envelope.New(ctx, envelope.Config{
    Dir:        "./var/envelope",
    RootSecret: rootSecretFromYourSecretBootstrapping, // ≥16 字节，勿硬编码
})
if err != nil { return err }

if err := svc.RegisterTenant(ctx, "acme"); err != nil { return err }

ct, err := svc.Encrypt(ctx, "acme", "order-1001", []byte("PII..."))
// ct.Version == 当前主密钥版本

newVer, err := svc.RotateKey(ctx)   // 轮换；旧密文不受影响

pt, ct2, err := svc.Decrypt(ctx, "acme", "order-1001")
// 旧数据仍按 ct2.Version（历史版本）解开

switch {
case errors.Is(err, envelope.ErrKeyVersionNotFound):
    var kv *envelope.KeyVersionError
    errors.As(err, &kv)
    log.Printf("缺少主密钥版本 %d", kv.Version)
case errors.Is(err, envelope.ErrTenantDenied):
    // 跨租户
case errors.Is(err, envelope.ErrTenantUnknown):
    // 未注册租户
}
```

日志（slog）只记录租户、ID、密钥版本号、当前版本号与判定依据（basis），
不记录明文、DEK、KEK、根密钥。

## 7. 本地验证

```bash
# 全部单测（-v 可看到每个用例打印的密钥版本与判定依据）
go test -v ./...

# 竞态检测（需要 cgo/gcc）
CGO_ENABLED=1 go test -race -v ./...
```

测试覆盖：

1. 轮换后旧数据按 v1 解密、新数据按 v2，多次轮换后旧版本仍保留
   （`TestRotateThenReadOldData`）；
2. 跨租户访问的三种可区分结果：自己命名空间找不到 → `ErrRecordNotFound`
   （路径隔离，无法探知存在性）；文件被挪进自己目录但 owner 头是别人
   → `ErrTenantDenied`（带双方租户）；未注册租户 → `ErrTenantUnknown`
   （`TestCrossTenantDenied`）；
3. 篡改 `keys.json` 制造“引用缺失密钥版本” → `ErrKeyVersionNotFound`，
   不静默降级（`TestMissingKeyVersionNotSilentlyFallback`）；
4. 篡改密文 → `ErrCiphertextCorrupt`，且不影响其它数据
   （`TestTamperedCiphertextRejected`）；
5. 8 个加密协程 + 持续解密校验协程与 5 次轮换并发：所有密文版本都真实存在、
   随时可解、重复写同一 ID 得到 `ErrRecordExists`（`TestConcurrentEncryptDecryptAndRotate`）；
6. 全目录扫描确认无明文业务数据、无根密钥落盘（`TestNoPlaintextKeyMaterialOnDisk`）；
7. 重启后版本/租户/密文状态一致（`TestRestartPersistence`）。

## 8. 安全边界与注意事项

- 本组件是**本地**方案：根密钥由调用方提供并只在内存中使用。生产环境应从
  受控的秘密引导机制注入，不要硬编码、不要提交到仓库。
- 轮换只“加新版本”，不删除旧版本；删除旧版本会导致对应历史密文永久不可解，
  当前实现不提供删除版本的接口。
- 数据密钥为一次性随机密钥，每条消息独立；nonce 使用 crypto/rand 生成。
