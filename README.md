<p align="center">
  <img src="https://img.shields.io/badge/Cangjie-JinguiSSL%20Bridge-c96b2c?style=for-the-badge&labelColor=1f2430" alt="JinguiSSL Bridge" />
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

本项目采用 `Apache License 2.0`。详见 `LICENSE`。
