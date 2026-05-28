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

## 快速开始

### 依赖

当前 GitCode hosted mirror 已可直接引用。  
如果你是在同一工作区里并排维护三个仓，继续使用 sibling-path 也没有问题；但对外消费时，推荐直接使用下面这组 hosted 依赖。

```toml
[dependencies]
jinguissl_core = { git = "git@gitcode:CjKu/Jingui-Core.git", branch = "main" }
jinguissl_contract = { git = "git@gitcode:cinyu/jinguiSSL.git", branch = "main" }
jinguissl_bridge = { git = "git@gitcode:CjKu/JinguiSSLBridge.git", branch = "main" }
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
