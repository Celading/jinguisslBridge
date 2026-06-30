<p align="center">
  <img src="https://img.shields.io/badge/Cangjie-JinguiSSL%20Bridge-c96b2c?style=for-the-badge&labelColor=1f2430" alt="JinguiSSL Bridge" />
  <img src="https://img.shields.io/badge/version-0.7.6-c96b2c?style=for-the-badge&labelColor=1f2430" alt="Version 0.7.6" />
  <img src="https://img.shields.io/badge/package-dynamic-805ad5?style=for-the-badge&labelColor=1f2430" alt="Dynamic Package" />
  <img src="https://img.shields.io/badge/focus-runtime%20bridge-3182ce?style=for-the-badge&labelColor=1f2430" alt="Runtime Bridge" />
  <img src="https://img.shields.io/badge/license-Apache%202.0-1f9d55?style=for-the-badge&labelColor=1f2430" alt="Apache 2.0" />
</p>
<div align="center">
<span style="font-weight:300;font-size:36px">JinguiSSL Bridge</span><br/>
<span style="font-weight:100;font-size:24px">面向动态库、桥接调用与运行时接入的 JinguiSSL 适配层</span>
<p align="center">
  <strong>把 contract 与 core 的能力，组织成更适合桥接消费的动态表面</strong><br/>
  <sub>Dynamic package · FFI-friendly wrappers · TLS / SSH startup helpers · structured verify</sub>
</p>
</div>

## 这是什么

`JinguiSSL-bridge` 面向的是“不是直接写纯库，而是要把能力接进别的运行时”的场景。

典型用途包括：

- 动态库封装
- FFI / native bridge
- 上层框架或运行时的桥接入口
- 把 `contract` 与 `core` 的能力重新组织成更适合调用侧消费的 API

## 当前能力

- artifact / facade / capability 信息暴露
- AES backend、startup readiness、自检与推荐路径
- ES256 / P-256 structured verify
- TLS alert / session ticket / record 级桥接函数
- HTTP client/server TLS 输入校验与材料准备桥接
- SSH KEX / transcript / startup helper
- C ABI wrappers for Ed25519, P-256, RSA, and bridge self-description
- 内置桥接样例，便于直接验证集成方式

## 当前分层说明

本仓库当前约 5.5k 行桥接实现直接封装 `JinguiSSL-contract` 的 `live.*` 表面，并将其与桥接逻辑耦合在一起。

因此 `JinguiSSL-bridge` 当前**不应被视为独立于 contract/live 之外的密码学加固层**。它的安全边界与 contract 和 core 一致。如果底层私钥操作不具备恒定时间保证，bridge 层也不应被当作独立的安全硬化层使用。

后续 live 层重构完成后，bridge 的依赖结构会随之调整。

## 快速开始

### 依赖

公开仓库默认使用远程 Git 依赖；本地 sibling checkout 仅建议作为开发时的临时覆盖。

```toml
[dependencies]
jinguissl_core = { git = "https://gitcode.com/CjKu/JinguiCore.git" }
jinguissl = { git = "https://gitcode.com/cinyu/jinguiSSL.git" }
jinguissl_bridge = { git = "https://gitcode.com/CjKu/JinguiSSLBridge.git" }
```

当前维护线的 `JinguiSSL-bridge` 源码采用 `Apache-2.0`，但 Bridge 依赖 `JinguiSSL-contract` 与 `JinguiSSL-core`，其中当前 Core 源码线采用 `LGPL-3.0-only`。如果你分发包含 Core 的动态库、构建产物或组合包，需要同时核对 Core 的许可证要求和本仓库许可证。正式合规判断请以许可证原文和你的发布形态为准。

### 示例：读取 bridge 自描述信息

```cangjie
import jinguissl_bridge.*

main() {
    let info = bridgeArtifactInfo()
    println(info.packageName)
    println(info.outputType)
    println(info.facadeImportPath)
}
```

## 附带样例

仓库里已经带了几组可以直接拿来跑的桥接样例：

- `examples/http-client-tls-bridge-smoke`
- `examples/http-server-attach-planning-bridge-smoke`
- `examples/ssh-library-bridge-smoke`
- `examples/es256-p256-structured-verify-bridge-smoke`
- `examples/external-c-runtime-smoke`

## 外部 C 调用说明

如果调用方是外部 C 程序，并且要通过 `dlopen` / `dlsym` 直接调用 Bridge 的 `@C` 导出符号，当前已验证的入口顺序是：

1. `CJ_MRT_CjRuntimeInit()`
2. `CJ_MRT_SetCommandLineArgs(argc, argv)`
3. `CJ_MRT_CjRuntimeStart(c_entry)`
4. 在 `c_entry` 内执行 `dlopen` / `dlsym` / Bridge C ABI 调用

`examples/external-c-runtime-smoke` 给出了一个最小 C smoke。它验证 `bridge_ffi_init` 的 `-1` / `-2` / `0` 返回码，以及当前九个 Ed25519 / P-256 / RSA C ABI 导出在 null-input 下返回 `-1`。

这条证明目前只覆盖本机 macOS `aarch64` Cangjie `cjnative` 运行时路径；它不声称 Linux、OpenHarmony、HarmonyOS、Windows、托管包消费或不进入 Cangjie runtime 的裸 `dlopen` 调用已经可用。

### RSA public-key C ABI

`rsa_pubkey_from_pkcs8(...)` 是保留的 C ABI 符号名。当前 `0.7.6` 行为为：

- 接受标准 RSA SPKI PEM：`-----BEGIN PUBLIC KEY-----`
- 保留旧版 PKCS#1 RSA public-key PEM：`-----BEGIN RSA PUBLIC KEY-----`
- 对非 RSA SPKI 输入返回 `-3`

返回码仍遵守当前 C ABI 约定：`0` 表示成功，`-1` 表示输入错误，`-2` 表示输出缓冲区不足，`-3` 表示解析、密码学或校验失败。

## 构建

```bash
cjpm build
```

如需验证样例，可分别进入对应 `examples/*` 目录执行 `cjpm build`。
如需运行 smoke 输出，可分别进入对应 `examples/*` 目录执行 `cjpm run`。

## 目录结构

```text
JinguiSSL-bridge/
├── src/jinguissl_bridge/   # 动态桥接公开表面
├── examples/               # 桥接样例
├── testdata/               # 证书、向量与测试素材
├── cjpm.toml
└── README.md
```

## 适合什么场景

- 需要把密码能力暴露给其他运行时
- 需要动态库而非纯静态包
- 需要在 TLS / SSH / X.509 能力之上再包一层适配接口
- 希望用更接近“桥接消费”的调用方式访问 JinguiSSL

## 许可证

本仓库源码采用 `Apache License 2.0`。详见 `LICENSE`。

依赖边界说明：当前维护线依赖 `JinguiSSL-core`，其源码线采用 `LGPL-3.0-only`。因此本仓库的 Apache 源码许可不取消 Core 依赖在组合分发、静态/动态链接、动态库发布或打包场景中的许可证义务。
