# DNSSEC ZSK 轮换演示（dnspython 权威 DNS + FastAPI 控制面）

单实例权威 DNS：为固定区域 `example.test.` 通过 **UDP** 返回带 DNSSEC 签名的
**A / DNSKEY / SOA** 记录，并给出**完整的 NSEC 否定应答证明**；预置**一把固定
KSK + 两把演示 ZSK**（ECDSA P-256 / 算法 13）。FastAPI 提供换钥控制面，实现
RFC 6781 风格的 **预发布（pre-publish）ZSK 轮换**，并强制执行两段缓存安全等待。

## 否定应答（NSEC）

区域在内存中始终维护一条 NSEC 链（每个权威 owner name 一条，按规范顺序，
最后一条指回 apex），`lookup()` 在**同一次状态快照**内生成答案并签名：

- **不存在的名称 → NXDOMAIN**：Authority 段带 SOA+RRSIG，以及
  - 覆盖 QNAME 的 NSEC（证明该名称不存在）；
  - 覆盖最接近 encloser 下通配符 `*.<closest-encloser>` 的 NSEC（证明没有
    通配符合成）；
  - 两条证明落在同一 NSEC 区间时只发一次（RFC 4035 §3.1.3.2）。
- **名称存在但查询类型不存在 → NODATA（NOERROR，空 Answer）**：Authority 段带
  SOA+RRSIG 与 owner name **精确匹配**的 NSEC，其 type bitmap 列出实际存在
  的类型（RFC 4035 §3.1.3.1）。
- NSEC 的 TTL 取 SOA MINIMUM（`SOA_TTL`，RFC 4035 §2.3）；bitmap 恒含
  `NSEC` 与 `RRSIG`。
- NSEC 与 SOA 都由**当前阶段的签名 ZSK** 签名；DNSKEY 由 KSK 签名。每次查询
  只取一次 `RotationState.view()`，所以一条应答里不会混入不同阶段的签名或证明。
- 区域外查询仍返回 **REFUSED**，不带 SOA/NSEC、不置 AA 位，Answer/Authority/
  Additional 全空，不泄露区域信息。

## 轮换状态机与等待逻辑

```
initial    DNSKEY = {KSK, ZSK1}          A/SOA/NSEC 由 ZSK1 签名
published  DNSKEY = {KSK, ZSK1, ZSK2}    A/SOA/NSEC 由 ZSK1 签名
switched   DNSKEY = {KSK, ZSK1, ZSK2}    A/SOA/NSEC 由 ZSK2 签名
retired    DNSKEY = {KSK, ZSK2}          A/SOA/NSEC 由 ZSK2 签名
```

| 步骤 | 端点 | 守卫条件 |
|---|---|---|
| 1. 发布新公钥 | `POST /rotate/publish` | 无（幂等） |
| 2. 切换签名 | `POST /rotate/switch` | 需等到 `t_publish + DNSKEY_TTL` |
| 3. 撤下旧公钥 | `POST /rotate/retire` | 需等到 `t_switch + max(A_TTL, SOA_TTL)` |

- `t_publish`：DNSKEY 答复**开始**包含 ZSK2 的时刻 = 不含 ZSK2 的旧 DNSKEY
  答复最后可能发出的时刻。加上 DNSKEY TTL 后，缓存里才不可能再有旧集合。
- `t_switch`：A 答复**开始**用 ZSK2 签名的时刻。签名 ZSK 同时签 A、SOA 和
  NSEC，故 retire 的等待取这些 RRset 中最长的 TTL（`max(A_TTL, SOA_TTL)`），
  保证缓存里不再有任何携带 ZSK1 签名的应答（包含否定应答）。
- 操作过早 → **409**，响应体带 `remaining_seconds`，并带 `Retry-After` 头；
  **状态不变，DNS 答复保持原样**。
- 重复已成功的操作 → **200 `changed:false`**，**不重新计时**。
- 顺序错误（未发布就切换 / 未切换就撤钥）→ **409 `invalid_order`**。
- 等待期间 DNS 照常应答（答复内容仍由当前已提交状态渲染）。
- `POST /rotate/reset`：演示辅助，回到 initial。

## 启动（Docker Compose）

```bash
docker compose up -d --build
docker compose logs -f
```

- Swagger UI: <http://127.0.0.1:8000/docs>（在此执行 publish/switch/retire）
- 权威 DNS: `udp/5353`（容器内非 root 监听；如需 53 端口，把映射改成
  `"53:5353/udp"`）

本地无 Docker 时等价运行：

```bash
pip install -r requirements-dev.txt   # 或仅 requirements.txt（不需要跑校验脚本时）
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

## 验证真实 UDP 答复

```bash
dig @127.0.0.1 -p 5353 app.example.test. A      +dnssec +noall +answer
dig @127.0.0.1 -p 5353 example.test.     DNSKEY +dnssec +noall +answer

# NXDOMAIN：不存在的名称，Authority 段应含 SOA+RRSIG 与 1~2 条 NSEC+RRSIG
dig @127.0.0.1 -p 5353 missing.example.test. A  +dnssec +noall +authority

# NODATA：名称存在但无该类型，NSEC 的 bitmap 不含 AAAA
dig @127.0.0.1 -p 5353 app.example.test. AAAA   +dnssec +noall +authority

# 区域外：REFUSED，无 SOA/NSEC，AA=0
dig @127.0.0.1 -p 5353 example.com. A           +dnssec
```

RRSIG 的 key tag 对照 `GET /status` 里的 `keys`（本仓库预置密钥：KSK=51564，
ZSK1=56878，ZSK2=20030），即可看到签名者（**含否定应答的 NSEC/SOA**）从 ZSK1
变为 ZSK2、DNSKEY 集合从 `{KSK,ZSK1}` → `{KSK,ZSK1,ZSK2}` → `{KSK,ZSK2}`。

> 说明：本演示服务器**总是**在应答中附带 RRSIG（生产服务器通常只在查询带
> DO=1 时附带），以便直接观察签名变化。

## 自动化端到端校验

```bash
python3 scripts/demo_check.py        # 正向轮换 + 否定应答，约 70 秒（两段 30s 等待）
python3 scripts/negative_check.py    # 只聚焦否定应答，同上等待
python3 scripts/negative_check.py --quick   # 跳过两段定时等待
python3 -m pytest tests/ -q          # 无网络的单元测试（NSEC 链/证明/签名者）
```

`scripts/demo_check.py`（99 项检查）：初始答复、乱序拒绝、过早操作 409+剩余
秒数、失败后答复不变、幂等不重计时、各阶段 UDP 答复内容，**每个阶段的
NXDOMAIN 与 NODATA 证明**（都做离线 `dns.dnssec.validate`，并核对签名者 key
tag），以及危险混用（新旧密钥/新旧否定证明）：

- **混用 1**：新 A（ZSK2 签名） × 旧缓存 DNSKEY（无 ZSK2）→ 必须验证失败
  —— 这正是 switch 要等 `t_publish + DNSKEY_TTL` 的原因；
- **混用 2**：旧 A（ZSK1 签名） × 新 DNSKEY（无 ZSK1）→ 必须验证失败
  —— 这正是 retire 要等 `t_switch + signing TTL` 的原因；
- **混用 3**：initial 阶段的 NXDOMAIN 证明（ZSK1 签名） × retired 阶段 DNSKEY
  （无 ZSK1）→ 必须验证失败（否定证明同样受轮换等待保护）。

## 配置（环境变量）

| 变量 | 默认 | 说明 |
|---|---|---|
| `ZONE_NAME` | `example.test` | 区域名 |
| `APP_LABEL` | `app` | 固定域名前缀（可含点以构造多级名；不允许 `*`） |
| `A_VALUE` | `192.0.2.10` | A 记录值（TEST-NET-1） |
| `A_TTL` / `DNSKEY_TTL` / `SOA_TTL` | `30` | 秒；两段等待与 NSEC TTL 按此计算 |
| `DNS_HOST` / `DNS_PORT` | `0.0.0.0` / `5353` | UDP 监听 |
| `KEYS_DIR` | `keys` | 预置密钥目录 |
| `SIG_INCEPTION_SKEW` / `SIG_LIFETIME` | `300` / `2592000` | 签名有效期 |

## 密钥

`keys/` 下为**固定**的演示密钥（提交在仓库中，可复现；严禁用于真实区域）：
`ksk.pem`（flags 257，签 DNSKEY）、`zsk1.pem`（旧 ZSK）、`zsk2.pem`（新 ZSK）。
重新生成：`python3 scripts/gen_keys.py keys --force`（会打印 DNSKEY/DS）。

## 结构

```
app/
  config.py      环境变量配置
  keys.py        加载 PEM 密钥，派生 DNSKEY / key tag
  zone.py        轮换状态机（计时/守卫）+ NSEC 链 + RRset 渲染与签名
  dns_server.py  线程化 UDP 权威服务器（dnspython 解析/组装报文）
  main.py        FastAPI 控制面（/rotate/*, /status, Swagger）
keys/            预置 KSK + 2×ZSK（PEM）
scripts/
  gen_keys.py        生成密钥（一次性）
  demo_check.py      端到端校验（99 项，含否定应答与新旧混用）
  negative_check.py  否定应答专项校验（NXDOMAIN/NODATA/区域外/各阶段签名者）
tests/
  test_negative.py   无网络单元测试（NSEC 链、证明覆盖、签名者一致性）
Dockerfile / docker-compose.yml / requirements*.txt
```

## 已知限制 / 遗留事项

- 轮换状态在内存中，进程重启即回 initial（单实例演示；生产需持久化 +
  重启后按已发答复重建计时锚点）。
- 仅 UDP；未实现 TCP（含截断后的 TCP 重试）、AXFR、NOTIFY。
- 否定应答只实现 **NSEC**；未实现 NSEC3/NSEC3PARAM，也没有 NSEC 白化
  （zone walking）防护。区域很小（apex + 一个名称），NSEC 链直接暴露全部
  名称，这在演示中是有意为之。
- 区域没有任何通配符记录，因此否定证明总是按“无通配符合成”生成；不支持
  由 `APP_LABEL` 配置出通配符 owner name。
- DNSKEY 仅由 KSK 签名（合法模型；不少部署会同时用 ZSK 签 DNSKEY）。
- 单 ZSK 对轮换（zsk1→zsk2）一次性流程；多轮/回滚/双签（double-signature）
  轮换未实现。
- 未做 DS 上报/父区检查（真实换 KSK 时才需要；本演示 KSK 固定）。
- 演示用固定 SOA serial；未提供 NS 记录。
