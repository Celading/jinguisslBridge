package jinguissl_bridge

import std.collection.HashMap
import jinguissl_core.crypto.aes.*
import jinguissl_core.crypto.bignum.BigNum
import jinguissl_core.crypto.chacha20.*
import jinguissl_core.crypto.compliance.*
import jinguissl_core.crypto.digest.{hmac, sha256, sha384, sha512, HashAlgorithm}
import jinguissl_core.crypto.ecc.*
import jinguissl_core.crypto.ed25519.*
import jinguissl_core.crypto.error.*
import jinguissl_core.crypto.rsa.*
import jinguissl_core.crypto.sm3.sm3
import jinguissl_core.crypto.sm4.{sm4Encrypt, sm4Decrypt}
import jinguissl_core.crypto.ssh.*
import jinguissl_core.crypto.tls.*
import jinguissl_core.crypto.utils.*
import jinguissl_core.crypto.x25519.*
import jinguissl_core.crypto.x509.*
import jinguissl.contract.{contractSmCapability, contractTrySmCapability, contractRequireSmCapability, ContractSmCapability, ContractSmCapabilityOutcome}
import jinguissl.live.*

public let BRIDGE_VERSION: String = "0.1.0"

private let BRIDGE_ES256_P256_COORDINATE_BYTES: Int64 = 32
private let BRIDGE_ES256_P256_DIGEST_BYTES: Int64 = 32

public class BridgeArtifactInfo {
    public let packageName: String
    public let outputType: String
    public let facadeImportPath: String
    public let directStdxTlsServerConfigBridge: Bool
    public let notes: Array<String>

    public init(
        packageName: String,
        outputType: String,
        facadeImportPath: String,
        directStdxTlsServerConfigBridge: Bool,
        notes: Array<String>
    ) {
        if (packageName.trimAscii().size == 0) {
            throw ContractException(ContractErrorCode.BadInput, "bridge package name must not be empty")
        }
        if (outputType.trimAscii().size == 0) {
            throw ContractException(ContractErrorCode.BadInput, "bridge output type must not be empty")
        }
        if (facadeImportPath.trimAscii().size == 0) {
            throw ContractException(ContractErrorCode.BadInput, "bridge facade import path must not be empty")
        }
        if (notes.size == 0) {
            throw ContractException(ContractErrorCode.BadInput, "bridge notes must not be empty")
        }
        this.packageName = packageName.trimAscii()
        this.outputType = outputType.trimAscii()
        this.facadeImportPath = facadeImportPath.trimAscii()
        this.directStdxTlsServerConfigBridge = directStdxTlsServerConfigBridge
        this.notes = notes.clone()
    }
}

public class BridgeEs256P256StructuredVerifyRequest {
    public let x: Array<Byte>
    public let y: Array<Byte>
    public let signedBytes: Array<Byte>
    public let derSignature: Array<Byte>

    public init(
        x: Array<Byte>,
        y: Array<Byte>,
        signedBytes: Array<Byte>,
        derSignature: Array<Byte>
    ) {
        if (
            x.size != BRIDGE_ES256_P256_COORDINATE_BYTES ||
            y.size != BRIDGE_ES256_P256_COORDINATE_BYTES ||
            derSignature.size == 0
        ) {
            throw ContractException(
                ContractErrorCode.BadInput,
                "bridge ES256/P-256 structured verify request fields are invalid"
            )
        }
        this.x = x.clone()
        this.y = y.clone()
        this.signedBytes = signedBytes.clone()
        this.derSignature = derSignature.clone()
    }
}

public class BridgeEs256P256StructuredVerifyResult {
    public let signatureVerified: Bool
    public let digestSha256: Array<Byte>

    public init(signatureVerified: Bool, digestSha256: Array<Byte>) {
        if (digestSha256.size != BRIDGE_ES256_P256_DIGEST_BYTES) {
            throw ContractException(
                ContractErrorCode.BadInput,
                "bridge ES256/P-256 structured verify digest must be 32 bytes"
            )
        }
        this.signatureVerified = signatureVerified
        this.digestSha256 = digestSha256.clone()
    }
}

public class BridgeEs256P256StructuredVerifyOutcome {
    public let ok: Bool
    public let message: String
    public let code: ?ContractErrorCode
    public let igniteCode: ?ContractIgniteCryptoErrorCode
    public let result: ?BridgeEs256P256StructuredVerifyResult

    public init(
        ok: Bool,
        message: String,
        code!: ?ContractErrorCode = None,
        igniteCode!: ?ContractIgniteCryptoErrorCode = None,
        result!: ?BridgeEs256P256StructuredVerifyResult = None
    ) {
        if (message.trimAscii().size == 0) {
            throw ContractException(
                ContractErrorCode.BadInput,
                "bridge ES256/P-256 structured verify outcome message must not be empty"
            )
        }
        if (ok) {
            match (code) {
                case Some(_) =>
                    throw ContractException(
                        ContractErrorCode.BadInput,
                        "bridge ES256/P-256 structured verify outcome code must be empty when ok is true"
                    )
                case None => ()
            }
            match (igniteCode) {
                case Some(_) =>
                    throw ContractException(
                        ContractErrorCode.BadInput,
                        "bridge ES256/P-256 structured verify outcome ignite code must be empty when ok is true"
                    )
                case None => ()
            }
            match (result) {
                case Some(_) => ()
                case None =>
                    throw ContractException(
                        ContractErrorCode.BadInput,
                        "bridge ES256/P-256 structured verify outcome result must exist when ok is true"
                    )
            }
        } else {
            match (code) {
                case Some(_) => ()
                case None =>
                    throw ContractException(
                        ContractErrorCode.BadInput,
                        "bridge ES256/P-256 structured verify outcome code must exist when ok is false"
                    )
            }
            match (igniteCode) {
                case Some(_) => ()
                case None =>
                    throw ContractException(
                        ContractErrorCode.BadInput,
                        "bridge ES256/P-256 structured verify outcome ignite code must exist when ok is false"
                    )
            }
            match (result) {
                case Some(_) =>
                    throw ContractException(
                        ContractErrorCode.BadInput,
                        "bridge ES256/P-256 structured verify outcome result must be empty when ok is false"
                    )
                case None => ()
            }
        }
        this.ok = ok
        this.message = message.trimAscii()
        this.code = code
        this.igniteCode = igniteCode
        this.result = result
    }
}

public class BridgeSshTranscript {
    public let clientVersionLine: Array<Byte>
    public let serverVersionLine: Array<Byte>
    public let encodedClientKexInit: Array<Byte>
    public let encodedServerKexInit: Array<Byte>

    public init(
        clientVersionLine: Array<Byte>,
        serverVersionLine: Array<Byte>,
        encodedClientKexInit: Array<Byte>,
        encodedServerKexInit: Array<Byte>
    ) {
        if (
            clientVersionLine.size == 0 ||
            serverVersionLine.size == 0 ||
            encodedClientKexInit.size == 0 ||
            encodedServerKexInit.size == 0
        ) {
            throw ContractException(
                ContractErrorCode.BadInput,
                "bridge SSH transcript fields must not be empty"
            )
        }
        this.clientVersionLine = clientVersionLine.clone()
        this.serverVersionLine = serverVersionLine.clone()
        this.encodedClientKexInit = encodedClientKexInit.clone()
        this.encodedServerKexInit = encodedServerKexInit.clone()
    }
}

public class BridgeSshNegotiatedAlgorithms {
    public let kexAlgorithm: String
    public let hostKeyAlgorithm: String
    public let clientToServerCipher: String
    public let serverToClientCipher: String
    public let clientToServerMac: String
    public let serverToClientMac: String
    public let clientToServerCompression: String
    public let serverToClientCompression: String

    public init(
        kexAlgorithm: String,
        hostKeyAlgorithm: String,
        clientToServerCipher: String,
        serverToClientCipher: String,
        clientToServerMac: String,
        serverToClientMac: String,
        clientToServerCompression!: String = "none",
        serverToClientCompression!: String = "none"
    ) {
        if (
            kexAlgorithm.trimAscii().size == 0 ||
            hostKeyAlgorithm.trimAscii().size == 0 ||
            clientToServerCipher.trimAscii().size == 0 ||
            serverToClientCipher.trimAscii().size == 0 ||
            clientToServerMac.trimAscii().size == 0 ||
            serverToClientMac.trimAscii().size == 0 ||
            clientToServerCompression.trimAscii().size == 0 ||
            serverToClientCompression.trimAscii().size == 0
        ) {
            throw ContractException(
                ContractErrorCode.BadInput,
                "bridge SSH negotiated algorithm fields must not be empty"
            )
        }
        this.kexAlgorithm = kexAlgorithm.trimAscii()
        this.hostKeyAlgorithm = hostKeyAlgorithm.trimAscii()
        this.clientToServerCipher = clientToServerCipher.trimAscii()
        this.serverToClientCipher = serverToClientCipher.trimAscii()
        this.clientToServerMac = clientToServerMac.trimAscii()
        this.serverToClientMac = serverToClientMac.trimAscii()
        this.clientToServerCompression = clientToServerCompression.trimAscii()
        this.serverToClientCompression = serverToClientCompression.trimAscii()
    }
}

public class BridgeSshClientKexInitX25519 {
    public let encodedClientInit: Array<Byte>
    public let clientPublicKey: Array<Byte>

    public init(encodedClientInit: Array<Byte>, clientPublicKey: Array<Byte>) {
        if (encodedClientInit.size == 0 || clientPublicKey.size != 32) {
            throw ContractException(
                ContractErrorCode.BadInput,
                "bridge SSH X25519 client init output is invalid"
            )
        }
        this.encodedClientInit = encodedClientInit.clone()
        this.clientPublicKey = clientPublicKey.clone()
    }
}

public class BridgeSshClientInitialHandshakeX25519Request {
    public let transcript: BridgeSshTranscript
    public let clientPrivateKey: Array<Byte>
    public let encodedClientInit: Array<Byte>
    public let encodedServerReply: Array<Byte>
    public let negotiated: BridgeSshNegotiatedAlgorithms
    public let encodedClientNewKeys: Array<Byte>
    public let encodedServerNewKeys: Array<Byte>
    public let policy: ContractSshHostVerificationPolicy

    public init(
        transcript: BridgeSshTranscript,
        clientPrivateKey: Array<Byte>,
        encodedClientInit: Array<Byte>,
        encodedServerReply: Array<Byte>,
        negotiated: BridgeSshNegotiatedAlgorithms,
        encodedClientNewKeys: Array<Byte>,
        encodedServerNewKeys: Array<Byte>,
        policy!: ContractSshHostVerificationPolicy = ContractSshHostVerificationPolicy()
    ) {
        if (
            clientPrivateKey.size != 32 ||
            encodedClientInit.size == 0 ||
            encodedServerReply.size == 0 ||
            encodedClientNewKeys.size == 0 ||
            encodedServerNewKeys.size == 0
        ) {
            throw ContractException(
                ContractErrorCode.BadInput,
                "bridge SSH client handshake request fields are invalid"
            )
        }
        this.transcript = transcript
        this.clientPrivateKey = clientPrivateKey.clone()
        this.encodedClientInit = encodedClientInit.clone()
        this.encodedServerReply = encodedServerReply.clone()
        this.negotiated = negotiated
        this.encodedClientNewKeys = encodedClientNewKeys.clone()
        this.encodedServerNewKeys = encodedServerNewKeys.clone()
        this.policy = policy
    }
}

public class BridgeSshServerInitialHandshakeX25519RsaPkcs8Request {
    public let transcript: BridgeSshTranscript
    public let serverPrivateKey: Array<Byte>
    public let encodedClientInit: Array<Byte>
    public let hostPrivateKeyPkcs8Pem: String
    public let negotiated: BridgeSshNegotiatedAlgorithms
    public let encodedClientNewKeys: Array<Byte>
    public let encodedServerNewKeys: Array<Byte>
    public let signatureAlgorithm: String
    public let serverPublicKey: Array<Byte>

    public init(
        transcript: BridgeSshTranscript,
        serverPrivateKey: Array<Byte>,
        encodedClientInit: Array<Byte>,
        hostPrivateKeyPkcs8Pem: String,
        negotiated: BridgeSshNegotiatedAlgorithms,
        encodedClientNewKeys: Array<Byte>,
        encodedServerNewKeys: Array<Byte>,
        signatureAlgorithm!: String = "rsa-sha2-256",
        serverPublicKey!: Array<Byte> = []
    ) {
        if (
            serverPrivateKey.size != 32 ||
            encodedClientInit.size == 0 ||
            hostPrivateKeyPkcs8Pem.trimAscii().size == 0 ||
            encodedClientNewKeys.size == 0 ||
            encodedServerNewKeys.size == 0 ||
            signatureAlgorithm.trimAscii().size == 0
        ) {
            throw ContractException(
                ContractErrorCode.BadInput,
                "bridge SSH RSA server handshake request fields are invalid"
            )
        }
        this.transcript = transcript
        this.serverPrivateKey = serverPrivateKey.clone()
        this.encodedClientInit = encodedClientInit.clone()
        this.hostPrivateKeyPkcs8Pem = hostPrivateKeyPkcs8Pem
        this.negotiated = negotiated
        this.encodedClientNewKeys = encodedClientNewKeys.clone()
        this.encodedServerNewKeys = encodedServerNewKeys.clone()
        this.signatureAlgorithm = signatureAlgorithm.trimAscii()
        this.serverPublicKey = serverPublicKey.clone()
    }
}

public class BridgeSshServerInitialHandshakeX25519EcdsaPkcs8Request {
    public let transcript: BridgeSshTranscript
    public let serverPrivateKey: Array<Byte>
    public let encodedClientInit: Array<Byte>
    public let hostPrivateKeyPkcs8Pem: String
    public let negotiated: BridgeSshNegotiatedAlgorithms
    public let encodedClientNewKeys: Array<Byte>
    public let encodedServerNewKeys: Array<Byte>
    public let serverPublicKey: Array<Byte>

    public init(
        transcript: BridgeSshTranscript,
        serverPrivateKey: Array<Byte>,
        encodedClientInit: Array<Byte>,
        hostPrivateKeyPkcs8Pem: String,
        negotiated: BridgeSshNegotiatedAlgorithms,
        encodedClientNewKeys: Array<Byte>,
        encodedServerNewKeys: Array<Byte>,
        serverPublicKey!: Array<Byte> = []
    ) {
        if (
            serverPrivateKey.size != 32 ||
            encodedClientInit.size == 0 ||
            hostPrivateKeyPkcs8Pem.trimAscii().size == 0 ||
            encodedClientNewKeys.size == 0 ||
            encodedServerNewKeys.size == 0
        ) {
            throw ContractException(
                ContractErrorCode.BadInput,
                "bridge SSH ECDSA server handshake request fields are invalid"
            )
        }
        this.transcript = transcript
        this.serverPrivateKey = serverPrivateKey.clone()
        this.encodedClientInit = encodedClientInit.clone()
        this.hostPrivateKeyPkcs8Pem = hostPrivateKeyPkcs8Pem
        this.negotiated = negotiated
        this.encodedClientNewKeys = encodedClientNewKeys.clone()
        this.encodedServerNewKeys = encodedServerNewKeys.clone()
        this.serverPublicKey = serverPublicKey.clone()
    }
}

public class BridgeSshServerInitialHandshakeX25519Ed25519SeedRequest {
    public let transcript: BridgeSshTranscript
    public let serverPrivateKey: Array<Byte>
    public let encodedClientInit: Array<Byte>
    public let hostPrivateKeySeed: Array<Byte>
    public let negotiated: BridgeSshNegotiatedAlgorithms
    public let encodedClientNewKeys: Array<Byte>
    public let encodedServerNewKeys: Array<Byte>
    public let serverPublicKey: Array<Byte>

    public init(
        transcript: BridgeSshTranscript,
        serverPrivateKey: Array<Byte>,
        encodedClientInit: Array<Byte>,
        hostPrivateKeySeed: Array<Byte>,
        negotiated: BridgeSshNegotiatedAlgorithms,
        encodedClientNewKeys: Array<Byte>,
        encodedServerNewKeys: Array<Byte>,
        serverPublicKey!: Array<Byte> = []
    ) {
        if (
            serverPrivateKey.size != 32 ||
            encodedClientInit.size == 0 ||
            hostPrivateKeySeed.size != 32 ||
            encodedClientNewKeys.size == 0 ||
            encodedServerNewKeys.size == 0
        ) {
            throw ContractException(
                ContractErrorCode.BadInput,
                "bridge SSH Ed25519 server handshake request fields are invalid"
            )
        }
        this.transcript = transcript
        this.serverPrivateKey = serverPrivateKey.clone()
        this.encodedClientInit = encodedClientInit.clone()
        this.hostPrivateKeySeed = hostPrivateKeySeed.clone()
        this.negotiated = negotiated
        this.encodedClientNewKeys = encodedClientNewKeys.clone()
        this.encodedServerNewKeys = encodedServerNewKeys.clone()
        this.serverPublicKey = serverPublicKey.clone()
    }
}

public class BridgeSshServerLibraryStartupX25519RsaPkcs8Request {
    public let handshake: BridgeSshServerInitialHandshakeX25519RsaPkcs8Request
    public let profile: ContractHttpSshStartupProfile
    public let requestedAesEngine: ContractAesEngineKind
    public let aesBackendHint: String

    public init(
        handshake: BridgeSshServerInitialHandshakeX25519RsaPkcs8Request,
        profile!: ContractHttpSshStartupProfile = ContractHttpSshStartupProfile.SshServerLibrary,
        requestedAesEngine!: ContractAesEngineKind = ContractAesEngineKind.Auto,
        aesBackendHint!: String = ""
    ) {
        this.handshake = handshake
        this.profile = profile
        this.requestedAesEngine = requestedAesEngine
        this.aesBackendHint = aesBackendHint.trimAscii()
    }
}

public class BridgeSshServerLibraryStartupX25519EcdsaPkcs8Request {
    public let handshake: BridgeSshServerInitialHandshakeX25519EcdsaPkcs8Request
    public let profile: ContractHttpSshStartupProfile
    public let requestedAesEngine: ContractAesEngineKind
    public let aesBackendHint: String

    public init(
        handshake: BridgeSshServerInitialHandshakeX25519EcdsaPkcs8Request,
        profile!: ContractHttpSshStartupProfile = ContractHttpSshStartupProfile.SshServerLibrary,
        requestedAesEngine!: ContractAesEngineKind = ContractAesEngineKind.Auto,
        aesBackendHint!: String = ""
    ) {
        this.handshake = handshake
        this.profile = profile
        this.requestedAesEngine = requestedAesEngine
        this.aesBackendHint = aesBackendHint.trimAscii()
    }
}

public class BridgeSshServerLibraryStartupX25519Ed25519SeedRequest {
    public let handshake: BridgeSshServerInitialHandshakeX25519Ed25519SeedRequest
    public let profile: ContractHttpSshStartupProfile
    public let requestedAesEngine: ContractAesEngineKind
    public let aesBackendHint: String

    public init(
        handshake: BridgeSshServerInitialHandshakeX25519Ed25519SeedRequest,
        profile!: ContractHttpSshStartupProfile = ContractHttpSshStartupProfile.SshServerLibrary,
        requestedAesEngine!: ContractAesEngineKind = ContractAesEngineKind.Auto,
        aesBackendHint!: String = ""
    ) {
        this.handshake = handshake
        this.profile = profile
        this.requestedAesEngine = requestedAesEngine
        this.aesBackendHint = aesBackendHint.trimAscii()
    }
}

public class BridgeSshClientLibraryStartupX25519Request {
    public let handshake: BridgeSshClientInitialHandshakeX25519Request
    public let profile: ContractHttpSshStartupProfile
    public let requestedAesEngine: ContractAesEngineKind
    public let aesBackendHint: String

    public init(
        handshake: BridgeSshClientInitialHandshakeX25519Request,
        profile!: ContractHttpSshStartupProfile = ContractHttpSshStartupProfile.SshClientLibrary,
        requestedAesEngine!: ContractAesEngineKind = ContractAesEngineKind.Auto,
        aesBackendHint!: String = ""
    ) {
        this.handshake = handshake
        this.profile = profile
        this.requestedAesEngine = requestedAesEngine
        this.aesBackendHint = aesBackendHint.trimAscii()
    }
}

public class BridgeSshHostSigningRsaPkcs8Request {
    public let hostPrivateKeyPkcs8Pem: String
    public let exchangeHash: Array<Byte>
    public let signatureAlgorithm: String

    public init(
        hostPrivateKeyPkcs8Pem: String,
        exchangeHash: Array<Byte>,
        signatureAlgorithm!: String = "rsa-sha2-256"
    ) {
        if (
            hostPrivateKeyPkcs8Pem.trimAscii().size == 0 ||
            exchangeHash.size == 0 ||
            signatureAlgorithm.trimAscii().size == 0
        ) {
            throw ContractException(
                ContractErrorCode.BadInput,
                "bridge SSH RSA host signing request fields are invalid"
            )
        }
        this.hostPrivateKeyPkcs8Pem = hostPrivateKeyPkcs8Pem
        this.exchangeHash = exchangeHash.clone()
        this.signatureAlgorithm = signatureAlgorithm.trimAscii()
    }
}

public class BridgeSshHostSigningEcdsaPkcs8Request {
    public let hostPrivateKeyPkcs8Pem: String
    public let exchangeHash: Array<Byte>

    public init(
        hostPrivateKeyPkcs8Pem: String,
        exchangeHash: Array<Byte>
    ) {
        if (
            hostPrivateKeyPkcs8Pem.trimAscii().size == 0 ||
            exchangeHash.size == 0
        ) {
            throw ContractException(
                ContractErrorCode.BadInput,
                "bridge SSH ECDSA host signing request fields are invalid"
            )
        }
        this.hostPrivateKeyPkcs8Pem = hostPrivateKeyPkcs8Pem
        this.exchangeHash = exchangeHash.clone()
    }
}

public class BridgeSshHostSigningEd25519SeedRequest {
    public let hostPrivateKeySeed: Array<Byte>
    public let exchangeHash: Array<Byte>

    public init(
        hostPrivateKeySeed: Array<Byte>,
        exchangeHash: Array<Byte>
    ) {
        if (
            hostPrivateKeySeed.size != 32 ||
            exchangeHash.size == 0
        ) {
            throw ContractException(
                ContractErrorCode.BadInput,
                "bridge SSH Ed25519 host signing request fields are invalid"
            )
        }
        this.hostPrivateKeySeed = hostPrivateKeySeed.clone()
        this.exchangeHash = exchangeHash.clone()
    }
}

public class BridgeHttpServerTlsConfigRequest {
    public let certificateChainPem: String
    public let privateKeyPem: String
    public let alpnProtocols: Array<String>
    public let requireHttp2Alpn: Bool

    public init(
        certificateChainPem: String,
        privateKeyPem: String,
        alpnProtocols!: Array<String> = ["h2", "http/1.1"],
        requireHttp2Alpn!: Bool = true
    ) {
        if (certificateChainPem.trimAscii().size == 0 || privateKeyPem.trimAscii().size == 0) {
            throw ContractException(
                ContractErrorCode.BadInput,
                "bridge HTTP server TLS config request fields are invalid"
            )
        }
        this.certificateChainPem = certificateChainPem
        this.privateKeyPem = privateKeyPem
        this.alpnProtocols = alpnProtocols.clone()
        this.requireHttp2Alpn = requireHttp2Alpn
    }
}

public class BridgeHttpServerAttachPlanRequest {
    public let tls: BridgeHttpServerTlsConfigRequest
    public let profile: ContractHttpSshStartupProfile
    public let requestedAesEngine: ContractAesEngineKind
    public let aesBackendHint: String

    public init(
        tls: BridgeHttpServerTlsConfigRequest,
        profile!: ContractHttpSshStartupProfile = ContractHttpSshStartupProfile.HttpServerLibrary,
        requestedAesEngine!: ContractAesEngineKind = ContractAesEngineKind.Auto,
        aesBackendHint!: String = ""
    ) {
        this.tls = tls
        this.profile = profile
        this.requestedAesEngine = requestedAesEngine
        this.aesBackendHint = aesBackendHint.trimAscii()
    }
}

public class BridgeHttpClientTlsTrustRequest {
    public let trustAnchorsPemBundle: String
    public let intermediatesPemBundle: String
    public let hostname: String
    public let validationTime: String
    public let pinPolicy: ContractX509PinPolicy
    public let policy: ContractTlsHttpNegotiationPolicy

    public init(
        trustAnchorsPemBundle: String,
        intermediatesPemBundle!: String = "",
        hostname!: String = "",
        validationTime!: String = "",
        pinPolicy!: ContractX509PinPolicy = ContractX509PinPolicy(),
        policy!: ContractTlsHttpNegotiationPolicy = ContractTlsHttpNegotiationPolicy()
    ) {
        if (trustAnchorsPemBundle.trimAscii().size == 0) {
            throw ContractException(
                ContractErrorCode.BadInput,
                "bridge HTTP client TLS trust request trust anchors must not be empty"
            )
        }
        this.trustAnchorsPemBundle = trustAnchorsPemBundle
        this.intermediatesPemBundle = intermediatesPemBundle
        this.hostname = hostname
        this.validationTime = validationTime
        this.pinPolicy = ContractX509PinPolicy(
            allowedLeafDerSha256: pinPolicy.allowedLeafDerSha256,
            allowedLeafSpkiSha256: pinPolicy.allowedLeafSpkiSha256
        )
        this.policy = ContractTlsHttpNegotiationPolicy(
            requireServerName: policy.requireServerName,
            allowedServerNames: policy.allowedServerNames,
            alpnPreference: policy.alpnPreference
        )
    }
}

public class BridgeHttpClientTlsPeerPemRequest {
    public let leafPem: String
    public let trust: BridgeHttpClientTlsTrustRequest

    public init(
        leafPem: String,
        trust: BridgeHttpClientTlsTrustRequest
    ) {
        if (leafPem.trimAscii().size == 0) {
            throw ContractException(
                ContractErrorCode.BadInput,
                "bridge HTTP client TLS peer PEM request leaf certificate must not be empty"
            )
        }
        this.leafPem = leafPem
        this.trust = trust
    }
}

public class BridgeHttpClientTlsPeerChainRequest {
    public let certificateChainPemBundle: String
    public let trust: BridgeHttpClientTlsTrustRequest

    public init(
        certificateChainPemBundle: String,
        trust: BridgeHttpClientTlsTrustRequest
    ) {
        if (certificateChainPemBundle.trimAscii().size == 0) {
            throw ContractException(
                ContractErrorCode.BadInput,
                "bridge HTTP client TLS peer chain request certificate chain must not be empty"
            )
        }
        this.certificateChainPemBundle = certificateChainPemBundle
        this.trust = trust
    }
}

public class BridgeHttpServerLibraryStartupRequest {
    public let tls: BridgeHttpServerTlsConfigRequest
    public let profile: ContractHttpSshStartupProfile
    public let requestedAesEngine: ContractAesEngineKind
    public let aesBackendHint: String

    public init(
        tls: BridgeHttpServerTlsConfigRequest,
        profile!: ContractHttpSshStartupProfile = ContractHttpSshStartupProfile.HttpServerLibrary,
        requestedAesEngine!: ContractAesEngineKind = ContractAesEngineKind.Auto,
        aesBackendHint!: String = ""
    ) {
        this.tls = tls
        this.profile = profile
        this.requestedAesEngine = requestedAesEngine
        this.aesBackendHint = aesBackendHint.trimAscii()
    }
}

public class BridgeHttpClientLibraryStartupRequest {
    public let trust: BridgeHttpClientTlsTrustRequest
    public let profile: ContractHttpSshStartupProfile
    public let requestedAesEngine: ContractAesEngineKind
    public let aesBackendHint: String

    public init(
        trust: BridgeHttpClientTlsTrustRequest,
        profile!: ContractHttpSshStartupProfile = ContractHttpSshStartupProfile.HttpClientLibrary,
        requestedAesEngine!: ContractAesEngineKind = ContractAesEngineKind.Auto,
        aesBackendHint!: String = ""
    ) {
        this.trust = trust
        this.profile = profile
        this.requestedAesEngine = requestedAesEngine
        this.aesBackendHint = aesBackendHint.trimAscii()
    }
}

public class BridgeTlsAlertPayloadRequest {
    public let level: ContractTlsAlertLevel
    public let description: ContractTlsAlertDescription

    public init(level: ContractTlsAlertLevel, description: ContractTlsAlertDescription) {
        this.level = level
        this.description = description
    }
}

public class BridgeTlsAlertPayloadDecodeRequest {
    public let encodedAlert: Array<Byte>

    public init(encodedAlert: Array<Byte>) {
        if (encodedAlert.size == 0) {
            throw ContractException(
                ContractErrorCode.BadInput,
                "bridge TLS alert payload decode request must not be empty"
            )
        }
        this.encodedAlert = encodedAlert.clone()
    }
}

public class BridgeTlsAlertRecordRequest {
    public let version: ContractTlsVersion
    public let level: ContractTlsAlertLevel
    public let description: ContractTlsAlertDescription

    public init(
        version: ContractTlsVersion,
        level: ContractTlsAlertLevel,
        description: ContractTlsAlertDescription
    ) {
        this.version = version
        this.level = level
        this.description = description
    }
}

public class BridgeTlsAlertRecordDecodeRequest {
    public let encodedRecord: Array<Byte>

    public init(encodedRecord: Array<Byte>) {
        if (encodedRecord.size == 0) {
            throw ContractException(
                ContractErrorCode.BadInput,
                "bridge TLS alert record decode request must not be empty"
            )
        }
        this.encodedRecord = encodedRecord.clone()
    }
}

public class BridgeTls12HttpClientHelloRequest {
    public let keyExchange: ContractTls12KeyExchange
    public let sessionId: Array<Byte>
    public let serverName: String
    public let alpnProtocols: Array<String>
    public let requestOcspStapling: Bool

    public init(
        keyExchange: ContractTls12KeyExchange,
        sessionId!: Array<Byte> = [],
        serverName!: String = "",
        alpnProtocols!: Array<String> = [],
        requestOcspStapling!: Bool = false
    ) {
        this.keyExchange = keyExchange
        this.sessionId = sessionId.clone()
        this.serverName = serverName
        this.alpnProtocols = alpnProtocols.clone()
        this.requestOcspStapling = requestOcspStapling
    }
}

public class BridgeTls12HttpServerHelloRequest {
    public let encodedClientHello: Array<Byte>
    public let keyExchange: ContractTls12KeyExchange

    public init(
        encodedClientHello: Array<Byte>,
        keyExchange: ContractTls12KeyExchange
    ) {
        if (encodedClientHello.size == 0) {
            throw ContractException(
                ContractErrorCode.BadInput,
                "bridge TLS1.2 HTTP ServerHello request encoded ClientHello must not be empty"
            )
        }
        this.encodedClientHello = encodedClientHello.clone()
        this.keyExchange = keyExchange
    }
}

public class BridgeTls12CertificateHandshakeFromPemChainRequest {
    public let certChainPemBundle: String

    public init(certChainPemBundle: String) {
        if (certChainPemBundle.trimAscii().size == 0) {
            throw ContractException(
                ContractErrorCode.BadInput,
                "bridge TLS1.2 certificate handshake request PEM bundle must not be empty"
            )
        }
        this.certChainPemBundle = certChainPemBundle
    }
}

public class BridgeTls12VerifyCertificateHandshakeForHttpRequest {
    public let encodedCertificateHandshake: Array<Byte>
    public let trust: BridgeHttpClientTlsTrustRequest

    public init(
        encodedCertificateHandshake: Array<Byte>,
        trust: BridgeHttpClientTlsTrustRequest
    ) {
        if (encodedCertificateHandshake.size == 0) {
            throw ContractException(
                ContractErrorCode.BadInput,
                "bridge TLS1.2 certificate verify request handshake must not be empty"
            )
        }
        this.encodedCertificateHandshake = encodedCertificateHandshake.clone()
        this.trust = trust
    }
}

public class BridgeTls12RsaClientKeyExchangeFromLeafPemRequest {
    public let serverLeafPem: String

    public init(serverLeafPem: String) {
        if (serverLeafPem.trimAscii().size == 0) {
            throw ContractException(
                ContractErrorCode.BadInput,
                "bridge TLS1.2 RSA ClientKeyExchange request server leaf certificate must not be empty"
            )
        }
        this.serverLeafPem = serverLeafPem
    }
}

public class BridgeTls12ProcessRsaClientKeyExchangeRequest {
    public let serverPrivateKeyPkcs8Pem: String
    public let encodedClientKeyExchange: Array<Byte>

    public init(
        serverPrivateKeyPkcs8Pem: String,
        encodedClientKeyExchange: Array<Byte>
    ) {
        if (
            serverPrivateKeyPkcs8Pem.trimAscii().size == 0 ||
            encodedClientKeyExchange.size == 0
        ) {
            throw ContractException(
                ContractErrorCode.BadInput,
                "bridge TLS1.2 RSA ClientKeyExchange process request fields are invalid"
            )
        }
        this.serverPrivateKeyPkcs8Pem = serverPrivateKeyPkcs8Pem
        this.encodedClientKeyExchange = encodedClientKeyExchange.clone()
    }
}

public class BridgeTls12DeriveSecretsFromPreMasterRequest {
    public let preMasterSecret: Array<Byte>
    public let clientRandom: Array<Byte>
    public let serverRandom: Array<Byte>
    public let keyLen: Int64
    public let ivLen: Int64

    public init(
        preMasterSecret: Array<Byte>,
        clientRandom: Array<Byte>,
        serverRandom: Array<Byte>,
        keyLen!: Int64 = 16,
        ivLen!: Int64 = 12
    ) {
        if (
            preMasterSecret.size == 0 ||
            clientRandom.size != 32 ||
            serverRandom.size != 32 ||
            keyLen <= 0 ||
            ivLen <= 0
        ) {
            throw ContractException(
                ContractErrorCode.BadInput,
                "bridge TLS1.2 pre-master secret derivation request fields are invalid"
            )
        }
        this.preMasterSecret = preMasterSecret.clone()
        this.clientRandom = clientRandom.clone()
        this.serverRandom = serverRandom.clone()
        this.keyLen = keyLen
        this.ivLen = ivLen
    }
}

public class BridgeTls12EcdheServerKeyExchangeRequest {
    public let keyExchange: ContractTls12KeyExchange
    public let serverPrivateScalar: ?Array<Byte>

    public init(
        keyExchange: ContractTls12KeyExchange,
        serverPrivateScalar!: ?Array<Byte> = None
    ) {
        if (let Some(value) <- serverPrivateScalar) {
            if (value.size == 0) {
                throw ContractException(
                    ContractErrorCode.BadInput,
                    "bridge TLS1.2 ECDHE server key exchange request scalar must not be empty"
                )
            }
            this.serverPrivateScalar = Some(value.clone())
        } else {
            this.serverPrivateScalar = None
        }
        this.keyExchange = keyExchange
    }
}

public class BridgeTls12EcdheClientKeyExchangeRequest {
    public let keyExchange: ContractTls12KeyExchange
    public let clientPrivateScalar: ?Array<Byte>

    public init(
        keyExchange: ContractTls12KeyExchange,
        clientPrivateScalar!: ?Array<Byte> = None
    ) {
        if (let Some(value) <- clientPrivateScalar) {
            if (value.size == 0) {
                throw ContractException(
                    ContractErrorCode.BadInput,
                    "bridge TLS1.2 ECDHE client key exchange request scalar must not be empty"
                )
            }
            this.clientPrivateScalar = Some(value.clone())
        } else {
            this.clientPrivateScalar = None
        }
        this.keyExchange = keyExchange
    }
}

public class BridgeTls12DeriveClientSecretsFromEcdheRequest {
    public let keyExchange: ContractTls12KeyExchange
    public let clientPrivateScalar: Array<Byte>
    public let encodedServerKeyExchange: Array<Byte>
    public let clientRandom: Array<Byte>
    public let serverRandom: Array<Byte>
    public let keyLen: Int64
    public let ivLen: Int64

    public init(
        keyExchange: ContractTls12KeyExchange,
        clientPrivateScalar: Array<Byte>,
        encodedServerKeyExchange: Array<Byte>,
        clientRandom: Array<Byte>,
        serverRandom: Array<Byte>,
        keyLen!: Int64 = 16,
        ivLen!: Int64 = 12
    ) {
        if (
            clientPrivateScalar.size == 0 ||
            encodedServerKeyExchange.size == 0 ||
            clientRandom.size != 32 ||
            serverRandom.size != 32 ||
            keyLen <= 0 ||
            ivLen <= 0
        ) {
            throw ContractException(
                ContractErrorCode.BadInput,
                "bridge TLS1.2 ECDHE client secret derivation request fields are invalid"
            )
        }
        this.keyExchange = keyExchange
        this.clientPrivateScalar = clientPrivateScalar.clone()
        this.encodedServerKeyExchange = encodedServerKeyExchange.clone()
        this.clientRandom = clientRandom.clone()
        this.serverRandom = serverRandom.clone()
        this.keyLen = keyLen
        this.ivLen = ivLen
    }
}

public class BridgeTls12DeriveServerSecretsFromEcdheRequest {
    public let keyExchange: ContractTls12KeyExchange
    public let serverPrivateScalar: Array<Byte>
    public let encodedClientKeyExchange: Array<Byte>
    public let clientRandom: Array<Byte>
    public let serverRandom: Array<Byte>
    public let keyLen: Int64
    public let ivLen: Int64

    public init(
        keyExchange: ContractTls12KeyExchange,
        serverPrivateScalar: Array<Byte>,
        encodedClientKeyExchange: Array<Byte>,
        clientRandom: Array<Byte>,
        serverRandom: Array<Byte>,
        keyLen!: Int64 = 16,
        ivLen!: Int64 = 12
    ) {
        if (
            serverPrivateScalar.size == 0 ||
            encodedClientKeyExchange.size == 0 ||
            clientRandom.size != 32 ||
            serverRandom.size != 32 ||
            keyLen <= 0 ||
            ivLen <= 0
        ) {
            throw ContractException(
                ContractErrorCode.BadInput,
                "bridge TLS1.2 ECDHE server secret derivation request fields are invalid"
            )
        }
        this.keyExchange = keyExchange
        this.serverPrivateScalar = serverPrivateScalar.clone()
        this.encodedClientKeyExchange = encodedClientKeyExchange.clone()
        this.clientRandom = clientRandom.clone()
        this.serverRandom = serverRandom.clone()
        this.keyLen = keyLen
        this.ivLen = ivLen
    }
}

public class BridgeTls12RecordChannelRequest {
    public let secrets: ContractTls12HandshakeSecrets
    public let algorithm: ContractAeadAlgorithm

    public init(
        secrets: ContractTls12HandshakeSecrets,
        algorithm!: ContractAeadAlgorithm = ContractAeadAlgorithm.Aes256Gcm
    ) {
        this.secrets = secrets
        this.algorithm = algorithm
    }
}

public class BridgeTls13HttpClientHelloX25519Request {
    public let serverName: String
    public let alpnProtocols: Array<String>
    public let clientPrivateKey: ?Array<Byte>

    public init(
        serverName: String,
        alpnProtocols!: Array<String> = [],
        clientPrivateKey!: ?Array<Byte> = None
    ) {
        if (serverName.trimAscii().size == 0) {
            throw ContractException(
                ContractErrorCode.BadInput,
                "bridge TLS1.3 HTTP ClientHello request server name must not be empty"
            )
        }
        if (let Some(value) <- clientPrivateKey) {
            if (value.size != 32) {
                throw ContractException(
                    ContractErrorCode.BadInput,
                    "bridge TLS1.3 HTTP ClientHello request private key must be 32 bytes"
                )
            }
            this.clientPrivateKey = Some(value.clone())
        } else {
            this.clientPrivateKey = None
        }
        this.serverName = serverName.trimAscii()
        this.alpnProtocols = alpnProtocols.clone()
    }
}

public class BridgeTls13HttpServerFlightX25519Request {
    public let encodedClientHello: Array<Byte>
    public let serverKeyExchangePrivate: Array<Byte>
    public let certChainPemBundle: String
    public let certificatePrivateKeyPkcs8Pem: String
    public let policy: ContractTlsHttpNegotiationPolicy

    public init(
        encodedClientHello: Array<Byte>,
        serverKeyExchangePrivate: Array<Byte>,
        certChainPemBundle: String,
        certificatePrivateKeyPkcs8Pem: String,
        policy!: ContractTlsHttpNegotiationPolicy = ContractTlsHttpNegotiationPolicy()
    ) {
        if (
            encodedClientHello.size == 0 ||
            serverKeyExchangePrivate.size != 32 ||
            certChainPemBundle.trimAscii().size == 0 ||
            certificatePrivateKeyPkcs8Pem.trimAscii().size == 0
        ) {
            throw ContractException(
                ContractErrorCode.BadInput,
                "bridge TLS1.3 HTTP server flight request fields are invalid"
            )
        }
        this.encodedClientHello = encodedClientHello.clone()
        this.serverKeyExchangePrivate = serverKeyExchangePrivate.clone()
        this.certChainPemBundle = certChainPemBundle
        this.certificatePrivateKeyPkcs8Pem = certificatePrivateKeyPkcs8Pem
        this.policy = ContractTlsHttpNegotiationPolicy(
            requireServerName: policy.requireServerName,
            allowedServerNames: policy.allowedServerNames,
            alpnPreference: policy.alpnPreference
        )
    }
}

public class BridgeTls13RecordChannelRequest {
    public let keyMaterial: ContractTls13ApplicationKeyMaterial
    public let algorithm: ContractAeadAlgorithm

    public init(
        keyMaterial: ContractTls13ApplicationKeyMaterial,
        algorithm!: ContractAeadAlgorithm = ContractAeadAlgorithm.Aes256Gcm
    ) {
        this.keyMaterial = keyMaterial
        this.algorithm = algorithm
    }
}

public class BridgeTls13HttpVerifyServerFlightX25519Request {
    public let clientHello: ContractTls13HttpClientHelloX25519
    public let serverFlight: ContractTls13HttpServerFlight
    public let trust: BridgeHttpClientTlsTrustRequest

    public init(
        clientHello: ContractTls13HttpClientHelloX25519,
        serverFlight: ContractTls13HttpServerFlight,
        trust: BridgeHttpClientTlsTrustRequest
    ) {
        this.clientHello = clientHello
        this.serverFlight = serverFlight
        this.trust = trust
    }
}

public class BridgeTls13ExporterMasterSecretRequest {
    public let masterSecret: Array<Byte>
    public let transcriptHash: Array<Byte>

    public init(masterSecret: Array<Byte>, transcriptHash: Array<Byte>) {
        if (masterSecret.size == 0 || transcriptHash.size == 0) {
            throw ContractException(
                ContractErrorCode.BadInput,
                "bridge TLS1.3 exporter master secret request fields must not be empty"
            )
        }
        this.masterSecret = masterSecret.clone()
        this.transcriptHash = transcriptHash.clone()
    }
}

public class BridgeTls13ExportKeyingMaterialRequest {
    public let exporterMasterSecret: Array<Byte>
    public let exporterLabel: String
    public let context: Array<Byte>
    public let outputLen: Int64

    public init(
        exporterMasterSecret: Array<Byte>,
        exporterLabel: String,
        context!: Array<Byte> = [],
        outputLen!: Int64 = 32
    ) {
        if (exporterMasterSecret.size == 0) {
            throw ContractException(
                ContractErrorCode.BadInput,
                "bridge TLS1.3 export keying material request exporter master secret must not be empty"
            )
        }
        if (exporterLabel.trimAscii().size == 0 || outputLen <= 0) {
            throw ContractException(
                ContractErrorCode.BadInput,
                "bridge TLS1.3 export keying material request fields are invalid"
            )
        }
        this.exporterMasterSecret = exporterMasterSecret.clone()
        this.exporterLabel = exporterLabel.trimAscii()
        this.context = context.clone()
        this.outputLen = outputLen
    }
}

public class BridgeTls13KeyUpdateRequest {
    public let currentTrafficSecret: Array<Byte>
    public let requestPeerUpdate: Bool
    public let keyLen: Int64
    public let ivLen: Int64

    public init(
        currentTrafficSecret: Array<Byte>,
        requestPeerUpdate!: Bool = false,
        keyLen!: Int64 = 16,
        ivLen!: Int64 = 12
    ) {
        if (currentTrafficSecret.size == 0 || keyLen <= 0 || ivLen <= 0) {
            throw ContractException(
                ContractErrorCode.BadInput,
                "bridge TLS1.3 key update request fields are invalid"
            )
        }
        this.currentTrafficSecret = currentTrafficSecret.clone()
        this.requestPeerUpdate = requestPeerUpdate
        this.keyLen = keyLen
        this.ivLen = ivLen
    }
}

public class BridgeTls13PeerKeyUpdateRequest {
    public let currentTrafficSecret: Array<Byte>
    public let encodedKeyUpdate: Array<Byte>
    public let keyLen: Int64
    public let ivLen: Int64

    public init(
        currentTrafficSecret: Array<Byte>,
        encodedKeyUpdate: Array<Byte>,
        keyLen!: Int64 = 16,
        ivLen!: Int64 = 12
    ) {
        if (currentTrafficSecret.size == 0 || encodedKeyUpdate.size == 0 || keyLen <= 0 || ivLen <= 0) {
            throw ContractException(
                ContractErrorCode.BadInput,
                "bridge TLS1.3 peer key update request fields are invalid"
            )
        }
        this.currentTrafficSecret = currentTrafficSecret.clone()
        this.encodedKeyUpdate = encodedKeyUpdate.clone()
        this.keyLen = keyLen
        this.ivLen = ivLen
    }
}

public class BridgeTls13KeyUpdateHandshakeRequest {
    public let requestPeerUpdate: Bool

    public init(requestPeerUpdate!: Bool = false) {
        this.requestPeerUpdate = requestPeerUpdate
    }
}

public class BridgeTls13KeyUpdateHandshakeDecodeRequest {
    public let encodedKeyUpdate: Array<Byte>

    public init(encodedKeyUpdate: Array<Byte>) {
        if (encodedKeyUpdate.size == 0) {
            throw ContractException(
                ContractErrorCode.BadInput,
                "bridge TLS1.3 KeyUpdate decode request payload must not be empty"
            )
        }
        this.encodedKeyUpdate = encodedKeyUpdate.clone()
    }
}

public class BridgeTls13PskClientHelloFromSessionTicketRequest {
    public let ticket: ContractTlsSessionTicket
    public let sessionId: Array<Byte>

    public init(
        ticket: ContractTlsSessionTicket,
        sessionId!: Array<Byte> = []
    ) {
        this.ticket = ticket
        this.sessionId = sessionId.clone()
    }
}

public class BridgeTls13PskClientHelloFromSessionTicketsRequest {
    public let tickets: Array<ContractTlsSessionTicket>
    public let sessionId: Array<Byte>

    public init(
        tickets: Array<ContractTlsSessionTicket>,
        sessionId!: Array<Byte> = []
    ) {
        if (tickets.size == 0) {
            throw ContractException(
                ContractErrorCode.BadInput,
                "bridge TLS1.3 PSK session ticket list must not be empty"
            )
        }
        this.tickets = tickets.clone()
        this.sessionId = sessionId.clone()
    }
}

public class BridgeTls13PskServerHelloFromSessionTicketRequest {
    public let encodedClientHello: Array<Byte>
    public let selectedIdentityIndex: Int64
    public let nowUnixSeconds: Int64

    public init(
        encodedClientHello: Array<Byte>,
        selectedIdentityIndex!: Int64 = 0,
        nowUnixSeconds!: Int64 = 0
    ) {
        if (encodedClientHello.size == 0 || selectedIdentityIndex < 0) {
            throw ContractException(
                ContractErrorCode.BadInput,
                "bridge TLS1.3 PSK ServerHello request fields are invalid"
            )
        }
        this.encodedClientHello = encodedClientHello.clone()
        this.selectedIdentityIndex = selectedIdentityIndex
        this.nowUnixSeconds = nowUnixSeconds
    }
}

public class BridgeTls13PskServerHelloBySessionTicketsRequest {
    public let encodedClientHello: Array<Byte>
    public let nowUnixSeconds: Int64

    public init(
        encodedClientHello: Array<Byte>,
        nowUnixSeconds!: Int64 = 0
    ) {
        if (encodedClientHello.size == 0) {
            throw ContractException(
                ContractErrorCode.BadInput,
                "bridge TLS1.3 PSK session ticket list ServerHello request payload must not be empty"
            )
        }
        this.encodedClientHello = encodedClientHello.clone()
        this.nowUnixSeconds = nowUnixSeconds
    }
}

public class BridgeTls13ExtractClientPskSessionTicketRequest {
    public let encodedClientHello: Array<Byte>
    public let selectedIdentityIndex: Int64

    public init(
        encodedClientHello: Array<Byte>,
        selectedIdentityIndex!: Int64 = 0
    ) {
        if (encodedClientHello.size == 0 || selectedIdentityIndex < 0) {
            throw ContractException(
                ContractErrorCode.BadInput,
                "bridge TLS1.3 extract client PSK session ticket request fields are invalid"
            )
        }
        this.encodedClientHello = encodedClientHello.clone()
        this.selectedIdentityIndex = selectedIdentityIndex
    }
}

public class BridgeTls13ExtractServerSelectedPskIdentityRequest {
    public let encodedServerHello: Array<Byte>

    public init(encodedServerHello: Array<Byte>) {
        if (encodedServerHello.size == 0) {
            throw ContractException(
                ContractErrorCode.BadInput,
                "bridge TLS1.3 extract selected PSK identity request payload must not be empty"
            )
        }
        this.encodedServerHello = encodedServerHello.clone()
    }
}

public class BridgeTls13CipherBindingRequest {
    public let cipherSuite: Int64

    public init(cipherSuite: Int64) {
        this.cipherSuite = cipherSuite
    }
}

public class BridgeTls13CipherBindingFromServerHelloRequest {
    public let encodedServerHello: Array<Byte>

    public init(encodedServerHello: Array<Byte>) {
        if (encodedServerHello.size == 0) {
            throw ContractException(
                ContractErrorCode.BadInput,
                "bridge TLS1.3 cipher binding ServerHello request payload must not be empty"
            )
        }
        this.encodedServerHello = encodedServerHello.clone()
    }
}

public class BridgeTls13CipherBindingFromServerFlightRequest {
    public let serverFlight: ContractTls13HttpServerFlight

    public init(serverFlight: ContractTls13HttpServerFlight) {
        this.serverFlight = serverFlight
    }
}

public class BridgeTls13HttpVerifiedSessionRequest {
    public let session: ContractTls13HttpClientVerifiedSession

    public init(session: ContractTls13HttpClientVerifiedSession) {
        this.session = session
    }
}

public class BridgeTls13HttpVerifiedSessionExportRequest {
    public let session: ContractTls13HttpClientVerifiedSession
    public let exporterLabel: String
    public let context: Array<Byte>
    public let outputLen: Int64

    public init(
        session: ContractTls13HttpClientVerifiedSession,
        exporterLabel: String,
        context!: Array<Byte> = [],
        outputLen!: Int64 = 32
    ) {
        if (exporterLabel.trimAscii().size == 0 || outputLen <= 0) {
            throw ContractException(
                ContractErrorCode.BadInput,
                "bridge TLS1.3 verified session export request fields are invalid"
            )
        }
        this.session = session
        this.exporterLabel = exporterLabel.trimAscii()
        this.context = context.clone()
        this.outputLen = outputLen
    }
}

public class BridgeTls13HttpVerifiedSessionKeyUpdateRequest {
    public let session: ContractTls13HttpClientVerifiedSession
    public let requestPeerUpdate: Bool

    public init(
        session: ContractTls13HttpClientVerifiedSession,
        requestPeerUpdate!: Bool = false
    ) {
        this.session = session
        this.requestPeerUpdate = requestPeerUpdate
    }
}

public class BridgeTls13HttpVerifiedSessionPeerKeyUpdateRequest {
    public let session: ContractTls13HttpClientVerifiedSession
    public let encodedKeyUpdate: Array<Byte>

    public init(
        session: ContractTls13HttpClientVerifiedSession,
        encodedKeyUpdate: Array<Byte>
    ) {
        if (encodedKeyUpdate.size == 0) {
            throw ContractException(
                ContractErrorCode.BadInput,
                "bridge TLS1.3 verified session peer key update request must not be empty"
            )
        }
        this.session = session
        this.encodedKeyUpdate = encodedKeyUpdate.clone()
    }
}

public class BridgeTls13PskClientHelloFromSessionCacheRequest {
    public let cache: ContractTlsSessionCache
    public let identity: ContractTlsSessionIdentity
    public let nowUnixSeconds: Int64
    public let sessionId: Array<Byte>

    public init(
        cache: ContractTlsSessionCache,
        identity: ContractTlsSessionIdentity,
        nowUnixSeconds!: Int64 = 0,
        sessionId!: Array<Byte> = []
    ) {
        this.cache = cache
        this.identity = identity
        this.nowUnixSeconds = nowUnixSeconds
        this.sessionId = sessionId.clone()
    }
}

public class BridgeTls13PskClientHelloFromSessionCacheWithPolicyRequest {
    public let cache: ContractTlsSessionCache
    public let identity: ContractTlsSessionIdentity
    public let policy: ContractTls13SessionTicketPolicy
    public let nowUnixSeconds: Int64
    public let sessionId: Array<Byte>

    public init(
        cache: ContractTlsSessionCache,
        identity: ContractTlsSessionIdentity,
        policy!: ContractTls13SessionTicketPolicy = ContractTls13SessionTicketPolicy(),
        nowUnixSeconds!: Int64 = 0,
        sessionId!: Array<Byte> = []
    ) {
        this.cache = cache
        this.identity = identity
        this.policy = ContractTls13SessionTicketPolicy(
            minRemainingTtlSeconds: policy.minRemainingTtlSeconds,
            renewBeforeExpirySeconds: policy.renewBeforeExpirySeconds,
            requiredServerName: policy.requiredServerName,
            requiredAlpnProtocol: policy.requiredAlpnProtocol
        )
        this.nowUnixSeconds = nowUnixSeconds
        this.sessionId = sessionId.clone()
    }
}

public class BridgeTls13SessionTicketLifecycleRequest {
    public let ticket: ContractTlsSessionTicket
    public let policy: ContractTls13SessionTicketPolicy
    public let nowUnixSeconds: Int64

    public init(
        ticket: ContractTlsSessionTicket,
        policy!: ContractTls13SessionTicketPolicy = ContractTls13SessionTicketPolicy(),
        nowUnixSeconds!: Int64 = 0
    ) {
        this.ticket = ticket
        this.policy = ContractTls13SessionTicketPolicy(
            minRemainingTtlSeconds: policy.minRemainingTtlSeconds,
            renewBeforeExpirySeconds: policy.renewBeforeExpirySeconds,
            requiredServerName: policy.requiredServerName,
            requiredAlpnProtocol: policy.requiredAlpnProtocol
        )
        this.nowUnixSeconds = nowUnixSeconds
    }
}

public class BridgeTls13NewSessionTicketRequest {
    public let ticket: ContractTlsSessionTicket
    public let ticketAgeAdd: Int64

    public init(
        ticket: ContractTlsSessionTicket,
        ticketAgeAdd!: Int64 = 0
    ) {
        this.ticket = ticket
        this.ticketAgeAdd = ticketAgeAdd
    }
}

public class BridgeTls13StoreNewSessionTicketRequest {
    public let cache: ContractTlsSessionCache
    public let encodedNewSessionTicket: Array<Byte>

    public init(
        cache: ContractTlsSessionCache,
        encodedNewSessionTicket: Array<Byte>
    ) {
        if (encodedNewSessionTicket.size == 0) {
            throw ContractException(
                ContractErrorCode.BadInput,
                "bridge TLS1.3 store NewSessionTicket request payload must not be empty"
            )
        }
        this.cache = cache
        this.encodedNewSessionTicket = encodedNewSessionTicket.clone()
    }
}

public class BridgeTls13PskEarlyDataFromSessionTicketRequest {
    public let ticket: ContractTlsSessionTicket
    public let sessionId: Array<Byte>
    public let keyLen: Int64
    public let ivLen: Int64

    public init(
        ticket: ContractTlsSessionTicket,
        sessionId!: Array<Byte> = [],
        keyLen!: Int64 = 16,
        ivLen!: Int64 = 12
    ) {
        if (keyLen <= 0 || ivLen <= 0) {
            throw ContractException(
                ContractErrorCode.BadInput,
                "bridge TLS1.3 PSK early data request key/iv lengths must be > 0"
            )
        }
        this.ticket = ticket
        this.sessionId = sessionId.clone()
        this.keyLen = keyLen
        this.ivLen = ivLen
    }
}

public class BridgeTls13PskEarlyDataFromSessionCacheRequest {
    public let cache: ContractTlsSessionCache
    public let identity: ContractTlsSessionIdentity
    public let nowUnixSeconds: Int64
    public let sessionId: Array<Byte>
    public let keyLen: Int64
    public let ivLen: Int64

    public init(
        cache: ContractTlsSessionCache,
        identity: ContractTlsSessionIdentity,
        nowUnixSeconds!: Int64 = 0,
        sessionId!: Array<Byte> = [],
        keyLen!: Int64 = 16,
        ivLen!: Int64 = 12
    ) {
        if (keyLen <= 0 || ivLen <= 0) {
            throw ContractException(
                ContractErrorCode.BadInput,
                "bridge TLS1.3 PSK early data cache request key/iv lengths must be > 0"
            )
        }
        this.cache = cache
        this.identity = identity
        this.nowUnixSeconds = nowUnixSeconds
        this.sessionId = sessionId.clone()
        this.keyLen = keyLen
        this.ivLen = ivLen
    }
}

public class BridgeTls13PskEarlyDataAcceptRequest {
    public let encodedClientHello: Array<Byte>
    public let nowUnixSeconds: Int64
    public let selectedIdentityIndex: Int64
    public let keyLen: Int64
    public let ivLen: Int64

    public init(
        encodedClientHello: Array<Byte>,
        nowUnixSeconds!: Int64 = 0,
        selectedIdentityIndex!: Int64 = -1,
        keyLen!: Int64 = 16,
        ivLen!: Int64 = 12
    ) {
        if (encodedClientHello.size == 0 || keyLen <= 0 || ivLen <= 0) {
            throw ContractException(
                ContractErrorCode.BadInput,
                "bridge TLS1.3 PSK early data accept request fields are invalid"
            )
        }
        this.encodedClientHello = encodedClientHello.clone()
        this.nowUnixSeconds = nowUnixSeconds
        this.selectedIdentityIndex = selectedIdentityIndex
        this.keyLen = keyLen
        this.ivLen = ivLen
    }
}

public class BridgeTls13PskEarlyDataAcceptWithReplayCacheRequest {
    public let encodedClientHello: Array<Byte>
    public let replayCache: ContractTls13EarlyDataReplayCache
    public let nowUnixSeconds: Int64
    public let selectedIdentityIndex: Int64
    public let keyLen: Int64
    public let ivLen: Int64
    public let replayTtlSeconds: Int64

    public init(
        encodedClientHello: Array<Byte>,
        replayCache: ContractTls13EarlyDataReplayCache,
        nowUnixSeconds!: Int64 = 0,
        selectedIdentityIndex!: Int64 = -1,
        keyLen!: Int64 = 16,
        ivLen!: Int64 = 12,
        replayTtlSeconds!: Int64 = 0
    ) {
        if (encodedClientHello.size == 0 || keyLen <= 0 || ivLen <= 0) {
            throw ContractException(
                ContractErrorCode.BadInput,
                "bridge TLS1.3 PSK early data replay-cache request fields are invalid"
            )
        }
        this.encodedClientHello = encodedClientHello.clone()
        this.replayCache = replayCache
        this.nowUnixSeconds = nowUnixSeconds
        this.selectedIdentityIndex = selectedIdentityIndex
        this.keyLen = keyLen
        this.ivLen = ivLen
        this.replayTtlSeconds = replayTtlSeconds
    }
}

public class BridgeTls13PskEarlyDataHttpAcceptRequest {
    public let encodedClientHello: Array<Byte>
    public let expectedServerName: String
    public let expectedAlpnProtocol: String
    public let nowUnixSeconds: Int64
    public let selectedIdentityIndex: Int64
    public let keyLen: Int64
    public let ivLen: Int64

    public init(
        encodedClientHello: Array<Byte>,
        expectedServerName!: String = "",
        expectedAlpnProtocol!: String = "",
        nowUnixSeconds!: Int64 = 0,
        selectedIdentityIndex!: Int64 = -1,
        keyLen!: Int64 = 16,
        ivLen!: Int64 = 12
    ) {
        if (encodedClientHello.size == 0 || keyLen <= 0 || ivLen <= 0) {
            throw ContractException(
                ContractErrorCode.BadInput,
                "bridge TLS1.3 HTTP early data accept request fields are invalid"
            )
        }
        this.encodedClientHello = encodedClientHello.clone()
        this.expectedServerName = expectedServerName.trimAscii().toAsciiLower()
        this.expectedAlpnProtocol = expectedAlpnProtocol.trimAscii().toAsciiLower()
        this.nowUnixSeconds = nowUnixSeconds
        this.selectedIdentityIndex = selectedIdentityIndex
        this.keyLen = keyLen
        this.ivLen = ivLen
    }
}

public class BridgeTls13PskEarlyDataHttpAcceptWithReplayCacheRequest {
    public let encodedClientHello: Array<Byte>
    public let replayCache: ContractTls13EarlyDataReplayCache
    public let expectedServerName: String
    public let expectedAlpnProtocol: String
    public let nowUnixSeconds: Int64
    public let selectedIdentityIndex: Int64
    public let keyLen: Int64
    public let ivLen: Int64
    public let replayTtlSeconds: Int64

    public init(
        encodedClientHello: Array<Byte>,
        replayCache: ContractTls13EarlyDataReplayCache,
        expectedServerName!: String = "",
        expectedAlpnProtocol!: String = "",
        nowUnixSeconds!: Int64 = 0,
        selectedIdentityIndex!: Int64 = -1,
        keyLen!: Int64 = 16,
        ivLen!: Int64 = 12,
        replayTtlSeconds!: Int64 = 0
    ) {
        if (encodedClientHello.size == 0 || keyLen <= 0 || ivLen <= 0) {
            throw ContractException(
                ContractErrorCode.BadInput,
                "bridge TLS1.3 HTTP early data replay-cache request fields are invalid"
            )
        }
        this.encodedClientHello = encodedClientHello.clone()
        this.replayCache = replayCache
        this.expectedServerName = expectedServerName.trimAscii().toAsciiLower()
        this.expectedAlpnProtocol = expectedAlpnProtocol.trimAscii().toAsciiLower()
        this.nowUnixSeconds = nowUnixSeconds
        this.selectedIdentityIndex = selectedIdentityIndex
        this.keyLen = keyLen
        this.ivLen = ivLen
        this.replayTtlSeconds = replayTtlSeconds
    }
}

public func bridgeArtifactInfo(): BridgeArtifactInfo {
    let capability = contractCapabilityInfo()
    BridgeArtifactInfo(
        "jinguissl_bridge",
        "dynamic",
        "import jinguissl_bridge.*",
        capability.directStdxTlsServerConfigBridge,
        [
            "dynamic bridge wraps jinguissl.contract stable facade for upper-layer consumers",
            "direct stdx.net.tls.TlsServerConfig bridge is not provided here",
            "use contract-style precheck and verify APIs before external TLS config construction"
        ]
    )
}

public func bridgeContractFacadeInfo(): ContractFacadeInfo {
    contractFacadeInfo()
}

public func bridgeContractCapabilityInfo(): ContractCapabilityInfo {
    contractCapabilityInfo()
}

public func bridgeAesListHardwareMountPoints(): Array<ContractAesHardwareMountPointInfo> {
    contractAesListHardwareMountPoints()
}

public func bridgeAesHardwareRoadmap(): Array<ContractAesHardwareRoadmapEntry> {
    contractAesHardwareRoadmap()
}

public func bridgeAesCurrentReleasePlan(
    requestedEngine!: ContractAesEngineKind = ContractAesEngineKind.Auto,
    backendHint!: String = ""
): ContractAesCurrentReleasePlanReport {
    contractAesCurrentReleasePlan(requestedEngine: requestedEngine, backendHint: backendHint)
}

public func bridgeRequireAesCurrentReleasePrimaryBackend(
    backendHint!: String = ""
): ContractAesCurrentReleasePlanReport {
    contractRequireAesCurrentReleasePrimaryBackend(backendHint: backendHint)
}

public func bridgeAesDefaultHardwareBackendHint(): String {
    contractAesDefaultHardwareBackendHint()
}

public func bridgeAesProbeHardware(backendHint!: String = ""): ContractAesHardwareProbeInfo {
    contractAesProbeHardware(backendHint: backendHint)
}

public func bridgeResolveAesEngine(
    requestedEngine!: ContractAesEngineKind = ContractAesEngineKind.Auto,
    backendHint!: String = ""
): ContractAesEngineInfo {
    contractResolveAesEngine(requestedEngine: requestedEngine, backendHint: backendHint)
}

public func bridgeTryResolveAesEngine(
    requestedEngine!: ContractAesEngineKind = ContractAesEngineKind.Auto,
    backendHint!: String = ""
): ContractAesEngineResolveOutcome {
    contractTryResolveAesEngine(requestedEngine: requestedEngine, backendHint: backendHint)
}

public func bridgeRequireAesAcceleratedBackend(
    backendHint!: String = ""
): ContractAesHardwareProbeInfo {
    contractRequireAesAcceleratedBackend(backendHint: backendHint)
}

public func bridgeInspectAesNativeBridge(
    spec: ContractAesNativeBridgeSpec,
    requestedEngine!: ContractAesEngineKind = ContractAesEngineKind.Auto
): ContractAesNativeBridgeDiagnostics {
    contractInspectAesNativeBridge(spec, requestedEngine: requestedEngine)
}

public func bridgeTryInspectAesNativeBridge(
    spec: ContractAesNativeBridgeSpec,
    requestedEngine!: ContractAesEngineKind = ContractAesEngineKind.Auto
): ContractAesNativeBridgeDiagnosticsOutcome {
    contractTryInspectAesNativeBridge(spec, requestedEngine: requestedEngine)
}

public func bridgeDescribeAesNativeBridgeCallShape(
    spec: ContractAesNativeBridgeSpec,
    keyBytes: Int64
): ContractAesNativeBridgeCallShapeInfo {
    contractDescribeAesNativeBridgeCallShape(spec, keyBytes)
}

public func bridgeRecommendAesBackend(): ContractAesBackendRecommendation {
    contractRecommendAesBackend()
}

public func bridgeAesStartupSelfCheck(
    requestedEngine!: ContractAesEngineKind = ContractAesEngineKind.Auto,
    backendHint!: String = ""
): ContractAesStartupSelfCheckReport {
    contractAesStartupSelfCheck(requestedEngine: requestedEngine, backendHint: backendHint)
}

public func bridgeHttpSshStartupReadiness(
    requestedAesEngine!: ContractAesEngineKind = ContractAesEngineKind.Auto,
    aesBackendHint!: String = ""
): ContractHttpSshStartupReadinessReport {
    contractHttpSshStartupReadiness(requestedAesEngine: requestedAesEngine, aesBackendHint: aesBackendHint)
}

public func bridgeTryHttpSshStartupReadiness(
    requestedAesEngine!: ContractAesEngineKind = ContractAesEngineKind.Auto,
    aesBackendHint!: String = ""
): ContractHttpSshStartupReadinessOutcome {
    contractTryHttpSshStartupReadiness(requestedAesEngine: requestedAesEngine, aesBackendHint: aesBackendHint)
}

public func bridgeRequireHttpSshStartupReadiness(
    policy!: ContractHttpSshStartupPolicy = ContractHttpSshStartupPolicy(),
    requestedAesEngine!: ContractAesEngineKind = ContractAesEngineKind.Auto,
    aesBackendHint!: String = ""
): ContractHttpSshStartupReadinessReport {
    contractRequireHttpSshStartupReadiness(
        policy: policy,
        requestedAesEngine: requestedAesEngine,
        aesBackendHint: aesBackendHint
    )
}

public func bridgeTryRequireHttpSshStartupReadiness(
    policy!: ContractHttpSshStartupPolicy = ContractHttpSshStartupPolicy(),
    requestedAesEngine!: ContractAesEngineKind = ContractAesEngineKind.Auto,
    aesBackendHint!: String = ""
): ContractHttpSshStartupReadinessOutcome {
    contractTryRequireHttpSshStartupReadiness(
        policy: policy,
        requestedAesEngine: requestedAesEngine,
        aesBackendHint: aesBackendHint
    )
}

public func bridgeDescribeHttpSshStartupProfile(
    profile: ContractHttpSshStartupProfile
): ContractHttpSshStartupProfileTemplate {
    contractDescribeHttpSshStartupProfile(profile)
}

public func bridgeListHttpSshStartupProfiles(): Array<ContractHttpSshStartupProfileTemplate> {
    contractListHttpSshStartupProfiles()
}

public func bridgeRequireHttpSshStartupProfile(
    profile: ContractHttpSshStartupProfile,
    requestedAesEngine!: ContractAesEngineKind = ContractAesEngineKind.Auto,
    aesBackendHint!: String = ""
): ContractHttpSshStartupReadinessReport {
    contractRequireHttpSshStartupProfile(
        profile,
        requestedAesEngine: requestedAesEngine,
        aesBackendHint: aesBackendHint
    )
}

public func bridgeTryRequireHttpSshStartupProfile(
    profile: ContractHttpSshStartupProfile,
    requestedAesEngine!: ContractAesEngineKind = ContractAesEngineKind.Auto,
    aesBackendHint!: String = ""
): ContractHttpSshStartupReadinessOutcome {
    contractTryRequireHttpSshStartupProfile(
        profile,
        requestedAesEngine: requestedAesEngine,
        aesBackendHint: aesBackendHint
    )
}

public func bridgeDescribeProviderConsumptionGate(
    path: ContractProviderConsumptionPath
): ContractProviderConsumptionGateReport {
    contractDescribeProviderConsumptionGate(path)
}

public func bridgeListProviderConsumptionGates(): Array<ContractProviderConsumptionGateReport> {
    contractListProviderConsumptionGates()
}

public func bridgeRequireProviderConsumptionGate(
    path: ContractProviderConsumptionPath
): ContractProviderConsumptionGateReport {
    contractRequireProviderConsumptionGate(path)
}

public func bridgeTryRequireProviderConsumptionGate(
    path: ContractProviderConsumptionPath
): ContractProviderConsumptionGateOutcome {
    contractTryRequireProviderConsumptionGate(path)
}

public func bridgeEs256P256VerifyStructured(
    x: Array<Byte>,
    y: Array<Byte>,
    signedBytes: Array<Byte>,
    derSignature: Array<Byte>
): BridgeEs256P256StructuredVerifyResult {
    bridgeEs256P256VerifyStructuredRequest(
        BridgeEs256P256StructuredVerifyRequest(x, y, signedBytes, derSignature)
    )
}

public func bridgeEs256P256VerifyStructuredRequest(
    request: BridgeEs256P256StructuredVerifyRequest
): BridgeEs256P256StructuredVerifyResult {
    let result = es256P256VerifyStructuredRequest(
        Es256P256StructuredVerifyRequest(
            request.x,
            request.y,
            request.signedBytes,
            request.derSignature
        )
    )
    BridgeEs256P256StructuredVerifyResult(result.signatureVerified, result.digestSha256)
}

public func bridgeTryEs256P256VerifyStructured(
    x: Array<Byte>,
    y: Array<Byte>,
    signedBytes: Array<Byte>,
    derSignature: Array<Byte>
): BridgeEs256P256StructuredVerifyOutcome {
    try {
        let request = BridgeEs256P256StructuredVerifyRequest(x, y, signedBytes, derSignature)
        bridgeTryEs256P256VerifyStructuredRequest(request)
    } catch (e: ContractException) {
        BridgeEs256P256StructuredVerifyOutcome(
            false,
            e.message,
            code: Some(e.code),
            igniteCode: Some(contractMapToIgniteCryptoErrorCode(e.code))
        )
    }
}

public func bridgeTryEs256P256VerifyStructuredRequest(
    request: BridgeEs256P256StructuredVerifyRequest
): BridgeEs256P256StructuredVerifyOutcome {
    try {
        let result = bridgeEs256P256VerifyStructuredRequest(request)
        let message = if (result.signatureVerified) {
            "ES256/P-256 signature verified"
        } else {
            "ES256/P-256 signature did not verify"
        }
        BridgeEs256P256StructuredVerifyOutcome(true, message, result: Some(result))
    } catch (e: ContractException) {
        BridgeEs256P256StructuredVerifyOutcome(
            false,
            e.message,
            code: Some(e.code),
            igniteCode: Some(contractMapToIgniteCryptoErrorCode(e.code))
        )
    } catch (e: CryptoException) {
        let code = contractMapCryptoExceptionToErrorCode(e, operation: "verify")
        BridgeEs256P256StructuredVerifyOutcome(
            false,
            "ES256/P-256 structured verify failed: ${e.message}",
            code: Some(code),
            igniteCode: Some(contractMapToIgniteCryptoErrorCode(code))
        )
    }
}

public func bridgeTlsEncodeAlertPayload(
    level: ContractTlsAlertLevel,
    description: ContractTlsAlertDescription
): Array<Byte> {
    contractTlsEncodeAlertPayload(level, description)
}

public func bridgeTlsEncodeAlertPayloadRequest(
    request: BridgeTlsAlertPayloadRequest
): Array<Byte> {
    contractTlsEncodeAlertPayloadRequest(
        ContractTlsAlertPayloadRequest(request.level, request.description)
    )
}

public func bridgeTlsDecodeAlertPayload(
    encodedAlert: Array<Byte>
): ContractTlsAlertMessage {
    contractTlsDecodeAlertPayload(encodedAlert)
}

public func bridgeTlsDecodeAlertPayloadRequest(
    request: BridgeTlsAlertPayloadDecodeRequest
): ContractTlsAlertMessage {
    contractTlsDecodeAlertPayloadRequest(
        ContractTlsAlertPayloadDecodeRequest(request.encodedAlert)
    )
}

public func bridgeTryTlsDecodeAlertPayload(
    encodedAlert: Array<Byte>
): ContractTlsAlertDecodeOutcome {
    contractTryTlsDecodeAlertPayload(encodedAlert)
}

public func bridgeTryTlsDecodeAlertPayloadRequest(
    request: BridgeTlsAlertPayloadDecodeRequest
): ContractTlsAlertDecodeOutcome {
    contractTryTlsDecodeAlertPayloadRequest(
        ContractTlsAlertPayloadDecodeRequest(request.encodedAlert)
    )
}

public func bridgeTlsEncodeAlertRecord(
    version: ContractTlsVersion,
    level: ContractTlsAlertLevel,
    description: ContractTlsAlertDescription
): Array<Byte> {
    contractTlsEncodeAlertRecord(version, level, description)
}

public func bridgeTlsEncodeAlertRecordRequest(
    request: BridgeTlsAlertRecordRequest
): Array<Byte> {
    contractTlsEncodeAlertRecordRequest(
        ContractTlsAlertRecordRequest(
            request.version,
            request.level,
            request.description
        )
    )
}

public func bridgeTlsDecodeAlertRecord(
    encodedRecord: Array<Byte>
): ContractTlsAlertMessage {
    contractTlsDecodeAlertRecord(encodedRecord)
}

public func bridgeTlsDecodeAlertRecordRequest(
    request: BridgeTlsAlertRecordDecodeRequest
): ContractTlsAlertMessage {
    contractTlsDecodeAlertRecordRequest(
        ContractTlsAlertRecordDecodeRequest(request.encodedRecord)
    )
}

public func bridgeTryTlsDecodeAlertRecord(
    encodedRecord: Array<Byte>
): ContractTlsAlertDecodeOutcome {
    contractTryTlsDecodeAlertRecord(encodedRecord)
}

public func bridgeTryTlsDecodeAlertRecordRequest(
    request: BridgeTlsAlertRecordDecodeRequest
): ContractTlsAlertDecodeOutcome {
    contractTryTlsDecodeAlertRecordRequest(
        ContractTlsAlertRecordDecodeRequest(request.encodedRecord)
    )
}

public func bridgeTlsIsCloseNotifyAlert(alert: ContractTlsAlertMessage): Bool {
    contractTlsIsCloseNotifyAlert(alert)
}

public func bridgeTlsCreateSessionTicket(
    identity: ContractTlsSessionIdentity,
    secret: Array<Byte>,
    nonce!: Array<Byte> = [],
    nowUnixSeconds!: Int64 = 0,
    ttlSeconds!: Int64 = 86400
): ContractTlsSessionTicket {
    contractTlsCreateSessionTicket(
        identity,
        secret,
        nonce: nonce,
        nowUnixSeconds: nowUnixSeconds,
        ttlSeconds: ttlSeconds
    )
}

public func bridgeTlsEncodeSessionTicket(ticket: ContractTlsSessionTicket): Array<Byte> {
    contractTlsEncodeSessionTicket(ticket)
}

public func bridgeTlsDecodeSessionTicket(encoded: Array<Byte>): ContractTlsSessionTicket {
    contractTlsDecodeSessionTicket(encoded)
}

public func bridgeTlsIsSessionTicketExpired(
    ticket: ContractTlsSessionTicket,
    nowUnixSeconds!: Int64 = 0
): Bool {
    contractTlsIsSessionTicketExpired(ticket, nowUnixSeconds: nowUnixSeconds)
}

public func bridgeSshBuildDefaultKexInitPacket(cookie!: Array<Byte> = []): Array<Byte> {
    sshEncodeKexInit(sshBuildDefaultKexInit(cookie: cookie))
}

public func bridgeSshBuildKexEcdhInitX25519(clientPrivateKey: Array<Byte>): BridgeSshClientKexInitX25519 {
    let (encodedClientInit, clientPublicKey) = sshBuildKexEcdhInitX25519(clientPrivateKey)
    BridgeSshClientKexInitX25519(encodedClientInit, clientPublicKey)
}

public func bridgeSshEncodeNewKeys(): Array<Byte> {
    sshEncodeNewKeys()
}

public func bridgeHkdfDeriveHttpSshKeySet(
    ikm: Array<Byte>,
    contextId!: String = "",
    outputLen!: Int64 = 32,
    salt!: Array<Byte> = []
): ContractHkdfHttpSshKeySet {
    contractHkdfDeriveHttpSshKeySet(
        ikm,
        contextId: contextId,
        outputLen: outputLen,
        salt: salt
    )
}

public func bridgeEncryptEnvelopeV1(
    algorithm: ContractAeadAlgorithm,
    kid: String,
    key: Array<Byte>,
    plaintext: Array<Byte>,
    aad!: Array<Byte> = []
): ContractAeadEnvelopeV1 {
    contractEncryptEnvelopeV1(
        algorithm,
        kid,
        key,
        plaintext,
        aad: aad
    )
}

public func bridgeEncryptEnvelopeJsonV1(
    algorithm: ContractAeadAlgorithm,
    kid: String,
    key: Array<Byte>,
    plaintext: Array<Byte>,
    aad!: Array<Byte> = []
): String {
    contractEncryptEnvelopeJsonV1(
        algorithm,
        kid,
        key,
        plaintext,
        aad: aad
    )
}

public func bridgeEncryptEnvelopeJsonLegacyV1(
    algorithm: ContractAeadAlgorithm,
    kid: String,
    key: Array<Byte>,
    plaintext: Array<Byte>,
    aad!: Array<Byte> = []
): String {
    contractEncryptEnvelopeJsonLegacyV1(
        algorithm,
        kid,
        key,
        plaintext,
        aad: aad
    )
}

public func bridgeDecryptEnvelopeV1(
    envelope: ContractAeadEnvelopeV1,
    keyRing: HashMap<String, Array<Byte>>,
    aadOverride!: ?Array<Byte> = None
): Array<Byte> {
    contractDecryptEnvelopeV1(
        envelope,
        keyRing,
        aadOverride: aadOverride
    )
}

public func bridgeDecryptEnvelopeJsonV1(
    envelopeJson: String,
    keyRing: HashMap<String, Array<Byte>>,
    aadOverride!: ?Array<Byte> = None
): Array<Byte> {
    contractDecryptEnvelopeJsonV1(
        envelopeJson,
        keyRing,
        aadOverride: aadOverride
    )
}

public func bridgeDecryptEnvelopeJsonCompatV1(
    envelopeJson: String,
    keyRing: HashMap<String, Array<Byte>>,
    aadOverride!: ?Array<Byte> = None
): Array<Byte> {
    contractDecryptEnvelopeJsonCompatV1(
        envelopeJson,
        keyRing,
        aadOverride: aadOverride
    )
}

public func bridgeTryDecryptEnvelopeV1(
    envelope: ContractAeadEnvelopeV1,
    keyRing: HashMap<String, Array<Byte>>,
    aadOverride!: ?Array<Byte> = None
): ContractEnvelopeOpenOutcome {
    contractTryDecryptEnvelopeV1(
        envelope,
        keyRing,
        aadOverride: aadOverride
    )
}

public func bridgeTryDecryptEnvelopeJsonV1(
    envelopeJson: String,
    keyRing: HashMap<String, Array<Byte>>,
    aadOverride!: ?Array<Byte> = None
): ContractEnvelopeOpenOutcome {
    contractTryDecryptEnvelopeJsonV1(
        envelopeJson,
        keyRing,
        aadOverride: aadOverride
    )
}

public func bridgeTryDecryptEnvelopeJsonCompatV1(
    envelopeJson: String,
    keyRing: HashMap<String, Array<Byte>>,
    aadOverride!: ?Array<Byte> = None
): ContractEnvelopeOpenOutcome {
    contractTryDecryptEnvelopeJsonCompatV1(
        envelopeJson,
        keyRing,
        aadOverride: aadOverride
    )
}

public func bridgeValidateHttpServerTlsConfigRequest(
    request: BridgeHttpServerTlsConfigRequest
): ContractHttpServerTlsConfigValidationResult {
    contractValidateHttpServerTlsConfigRequest(
        ContractHttpServerTlsConfigRequest(
            request.certificateChainPem,
            request.privateKeyPem,
            alpnProtocols: request.alpnProtocols,
            requireHttp2Alpn: request.requireHttp2Alpn
        )
    )
}

public func bridgeTryValidateHttpServerTlsConfigRequest(
    request: BridgeHttpServerTlsConfigRequest
): ContractHttpServerTlsConfigValidationOutcome {
    contractTryValidateHttpServerTlsConfigRequest(
        ContractHttpServerTlsConfigRequest(
            request.certificateChainPem,
            request.privateKeyPem,
            alpnProtocols: request.alpnProtocols,
            requireHttp2Alpn: request.requireHttp2Alpn
        )
    )
}

public func bridgeValidateHttpServerTlsConfigInput(
    certificateChainPem: String,
    privateKeyPem: String,
    alpnProtocols!: Array<String> = ["h2", "http/1.1"],
    requireHttp2Alpn!: Bool = true
): ContractHttpServerTlsConfigValidationResult {
    contractValidateHttpServerTlsConfigInput(
        certificateChainPem,
        privateKeyPem,
        alpnProtocols: alpnProtocols,
        requireHttp2Alpn: requireHttp2Alpn
    )
}

public func bridgeTryValidateHttpServerTlsConfigInput(
    certificateChainPem: String,
    privateKeyPem: String,
    alpnProtocols!: Array<String> = ["h2", "http/1.1"],
    requireHttp2Alpn!: Bool = true
): ContractHttpServerTlsConfigValidationOutcome {
    contractTryValidateHttpServerTlsConfigInput(
        certificateChainPem,
        privateKeyPem,
        alpnProtocols: alpnProtocols,
        requireHttp2Alpn: requireHttp2Alpn
    )
}

public func bridgePrepareHttpServerTlsMaterialRequest(
    request: BridgeHttpServerTlsConfigRequest
): ContractHttpServerTlsMaterial {
    contractPrepareHttpServerTlsMaterialRequest(
        ContractHttpServerTlsConfigRequest(
            request.certificateChainPem,
            request.privateKeyPem,
            alpnProtocols: request.alpnProtocols,
            requireHttp2Alpn: request.requireHttp2Alpn
        )
    )
}

public func bridgeTryPrepareHttpServerTlsMaterialRequest(
    request: BridgeHttpServerTlsConfigRequest
): ContractHttpServerTlsMaterialOutcome {
    contractTryPrepareHttpServerTlsMaterialRequest(
        ContractHttpServerTlsConfigRequest(
            request.certificateChainPem,
            request.privateKeyPem,
            alpnProtocols: request.alpnProtocols,
            requireHttp2Alpn: request.requireHttp2Alpn
        )
    )
}

public func bridgePrepareHttpServerTlsMaterial(
    certificateChainPem: String,
    privateKeyPem: String,
    alpnProtocols!: Array<String> = ["h2", "http/1.1"],
    requireHttp2Alpn!: Bool = true
): ContractHttpServerTlsMaterial {
    contractPrepareHttpServerTlsMaterial(
        certificateChainPem,
        privateKeyPem,
        alpnProtocols: alpnProtocols,
        requireHttp2Alpn: requireHttp2Alpn
    )
}

public func bridgeTryPrepareHttpServerTlsMaterial(
    certificateChainPem: String,
    privateKeyPem: String,
    alpnProtocols!: Array<String> = ["h2", "http/1.1"],
    requireHttp2Alpn!: Bool = true
): ContractHttpServerTlsMaterialOutcome {
    contractTryPrepareHttpServerTlsMaterial(
        certificateChainPem,
        privateKeyPem,
        alpnProtocols: alpnProtocols,
        requireHttp2Alpn: requireHttp2Alpn
    )
}

public func bridgeValidateHttpClientTlsTrustRequest(
    request: BridgeHttpClientTlsTrustRequest
): ContractHttpClientTlsConfigValidationResult {
    contractValidateHttpClientTlsTrustRequest(
        ContractHttpClientTlsTrustRequest(
            request.trustAnchorsPemBundle,
            intermediatesPemBundle: request.intermediatesPemBundle,
            hostname: request.hostname,
            validationTime: request.validationTime,
            pinPolicy: request.pinPolicy,
            policy: request.policy
        )
    )
}

public func bridgeTryValidateHttpClientTlsTrustRequest(
    request: BridgeHttpClientTlsTrustRequest
): ContractHttpClientTlsConfigValidationOutcome {
    contractTryValidateHttpClientTlsTrustRequest(
        ContractHttpClientTlsTrustRequest(
            request.trustAnchorsPemBundle,
            intermediatesPemBundle: request.intermediatesPemBundle,
            hostname: request.hostname,
            validationTime: request.validationTime,
            pinPolicy: request.pinPolicy,
            policy: request.policy
        )
    )
}

public func bridgeValidateHttpClientTlsConfigInput(
    trustAnchorsPemBundle: String,
    intermediatesPemBundle!: String = "",
    hostname!: String = "",
    validationTime!: String = "",
    pinPolicy!: ContractX509PinPolicy = ContractX509PinPolicy(),
    policy!: ContractTlsHttpNegotiationPolicy = ContractTlsHttpNegotiationPolicy()
): ContractHttpClientTlsConfigValidationResult {
    contractValidateHttpClientTlsConfigInput(
        trustAnchorsPemBundle,
        intermediatesPemBundle: intermediatesPemBundle,
        hostname: hostname,
        validationTime: validationTime,
        pinPolicy: pinPolicy,
        policy: policy
    )
}

public func bridgeTryValidateHttpClientTlsConfigInput(
    trustAnchorsPemBundle: String,
    intermediatesPemBundle!: String = "",
    hostname!: String = "",
    validationTime!: String = "",
    pinPolicy!: ContractX509PinPolicy = ContractX509PinPolicy(),
    policy!: ContractTlsHttpNegotiationPolicy = ContractTlsHttpNegotiationPolicy()
): ContractHttpClientTlsConfigValidationOutcome {
    contractTryValidateHttpClientTlsConfigInput(
        trustAnchorsPemBundle,
        intermediatesPemBundle: intermediatesPemBundle,
        hostname: hostname,
        validationTime: validationTime,
        pinPolicy: pinPolicy,
        policy: policy
    )
}

public func bridgePrepareHttpClientTlsTrustMaterialRequest(
    request: BridgeHttpClientTlsTrustRequest
): ContractHttpClientTlsTrustMaterial {
    contractPrepareHttpClientTlsTrustMaterialRequest(
        ContractHttpClientTlsTrustRequest(
            request.trustAnchorsPemBundle,
            intermediatesPemBundle: request.intermediatesPemBundle,
            hostname: request.hostname,
            validationTime: request.validationTime,
            pinPolicy: request.pinPolicy,
            policy: request.policy
        )
    )
}

public func bridgeTryPrepareHttpClientTlsTrustMaterialRequest(
    request: BridgeHttpClientTlsTrustRequest
): ContractHttpClientTlsTrustMaterialOutcome {
    contractTryPrepareHttpClientTlsTrustMaterialRequest(
        ContractHttpClientTlsTrustRequest(
            request.trustAnchorsPemBundle,
            intermediatesPemBundle: request.intermediatesPemBundle,
            hostname: request.hostname,
            validationTime: request.validationTime,
            pinPolicy: request.pinPolicy,
            policy: request.policy
        )
    )
}

private func bridgeToContractHttpServerTlsConfigRequest(
    request: BridgeHttpServerTlsConfigRequest
): ContractHttpServerTlsConfigRequest {
    ContractHttpServerTlsConfigRequest(
        request.certificateChainPem,
        request.privateKeyPem,
        alpnProtocols: request.alpnProtocols,
        requireHttp2Alpn: request.requireHttp2Alpn
    )
}

private func bridgeToContractHttpClientTlsTrustRequest(
    request: BridgeHttpClientTlsTrustRequest
): ContractHttpClientTlsTrustRequest {
    ContractHttpClientTlsTrustRequest(
        request.trustAnchorsPemBundle,
        intermediatesPemBundle: request.intermediatesPemBundle,
        hostname: request.hostname,
        validationTime: request.validationTime,
        pinPolicy: request.pinPolicy,
        policy: request.policy
    )
}

public func bridgePrepareHttpServerLibraryStartupRequest(
    request: BridgeHttpServerLibraryStartupRequest
): ContractHttpServerLibraryStartupBundle {
    contractPrepareHttpServerLibraryStartupRequest(
        ContractHttpServerLibraryStartupRequest(
            bridgeToContractHttpServerTlsConfigRequest(request.tls),
            profile: request.profile,
            requestedAesEngine: request.requestedAesEngine,
            aesBackendHint: request.aesBackendHint
        )
    )
}

public func bridgeTryPrepareHttpServerLibraryStartupRequest(
    request: BridgeHttpServerLibraryStartupRequest
): ContractHttpServerLibraryStartupOutcome {
    contractTryPrepareHttpServerLibraryStartupRequest(
        ContractHttpServerLibraryStartupRequest(
            bridgeToContractHttpServerTlsConfigRequest(request.tls),
            profile: request.profile,
            requestedAesEngine: request.requestedAesEngine,
            aesBackendHint: request.aesBackendHint
        )
    )
}

public func bridgePlanHttpServerAttachRequest(
    request: BridgeHttpServerAttachPlanRequest
): ContractHttpServerAttachPlan {
    contractPlanHttpServerAttachRequest(
        ContractHttpServerLibraryStartupRequest(
            bridgeToContractHttpServerTlsConfigRequest(request.tls),
            profile: request.profile,
            requestedAesEngine: request.requestedAesEngine,
            aesBackendHint: request.aesBackendHint
        )
    )
}

public func bridgePlanHttpServerAttach(
    certificateChainPem: String,
    privateKeyPem: String,
    alpnProtocols!: Array<String> = ["h2", "http/1.1"],
    requireHttp2Alpn!: Bool = true,
    profile!: ContractHttpSshStartupProfile = ContractHttpSshStartupProfile.HttpServerLibrary,
    requestedAesEngine!: ContractAesEngineKind = ContractAesEngineKind.Auto,
    aesBackendHint!: String = ""
): ContractHttpServerAttachPlan {
    bridgePlanHttpServerAttachRequest(
        BridgeHttpServerAttachPlanRequest(
            BridgeHttpServerTlsConfigRequest(
                certificateChainPem,
                privateKeyPem,
                alpnProtocols: alpnProtocols,
                requireHttp2Alpn: requireHttp2Alpn
            ),
            profile: profile,
            requestedAesEngine: requestedAesEngine,
            aesBackendHint: aesBackendHint
        )
    )
}

public func bridgePrepareHttpClientLibraryStartupRequest(
    request: BridgeHttpClientLibraryStartupRequest
): ContractHttpClientLibraryStartupBundle {
    contractPrepareHttpClientLibraryStartupRequest(
        ContractHttpClientLibraryStartupRequest(
            bridgeToContractHttpClientTlsTrustRequest(request.trust),
            profile: request.profile,
            requestedAesEngine: request.requestedAesEngine,
            aesBackendHint: request.aesBackendHint
        )
    )
}

public func bridgeTryPrepareHttpClientLibraryStartupRequest(
    request: BridgeHttpClientLibraryStartupRequest
): ContractHttpClientLibraryStartupOutcome {
    contractTryPrepareHttpClientLibraryStartupRequest(
        ContractHttpClientLibraryStartupRequest(
            bridgeToContractHttpClientTlsTrustRequest(request.trust),
            profile: request.profile,
            requestedAesEngine: request.requestedAesEngine,
            aesBackendHint: request.aesBackendHint
        )
    )
}

public func bridgePrepareHttpClientTlsTrustMaterial(
    trustAnchorsPemBundle: String,
    intermediatesPemBundle!: String = "",
    hostname!: String = "",
    validationTime!: String = "",
    pinPolicy!: ContractX509PinPolicy = ContractX509PinPolicy(),
    policy!: ContractTlsHttpNegotiationPolicy = ContractTlsHttpNegotiationPolicy()
): ContractHttpClientTlsTrustMaterial {
    contractPrepareHttpClientTlsTrustMaterial(
        trustAnchorsPemBundle,
        intermediatesPemBundle: intermediatesPemBundle,
        hostname: hostname,
        validationTime: validationTime,
        pinPolicy: pinPolicy,
        policy: policy
    )
}

public func bridgeTryPrepareHttpClientTlsTrustMaterial(
    trustAnchorsPemBundle: String,
    intermediatesPemBundle!: String = "",
    hostname!: String = "",
    validationTime!: String = "",
    pinPolicy!: ContractX509PinPolicy = ContractX509PinPolicy(),
    policy!: ContractTlsHttpNegotiationPolicy = ContractTlsHttpNegotiationPolicy()
): ContractHttpClientTlsTrustMaterialOutcome {
    contractTryPrepareHttpClientTlsTrustMaterial(
        trustAnchorsPemBundle,
        intermediatesPemBundle: intermediatesPemBundle,
        hostname: hostname,
        validationTime: validationTime,
        pinPolicy: pinPolicy,
        policy: policy
    )
}

public func bridgeVerifyHttpClientPeerCertificatePemRequest(
    request: BridgeHttpClientTlsPeerPemRequest
): ContractX509VerifyResult {
    contractVerifyHttpClientPeerCertificatePemRequest(
        ContractHttpClientTlsPeerPemRequest(
            request.leafPem,
            ContractHttpClientTlsTrustRequest(
                request.trust.trustAnchorsPemBundle,
                intermediatesPemBundle: request.trust.intermediatesPemBundle,
                hostname: request.trust.hostname,
                validationTime: request.trust.validationTime,
                pinPolicy: request.trust.pinPolicy,
                policy: request.trust.policy
            )
        )
    )
}

public func bridgeTryVerifyHttpClientPeerCertificatePemRequest(
    request: BridgeHttpClientTlsPeerPemRequest
): ContractX509VerifyOutcome {
    contractTryVerifyHttpClientPeerCertificatePemRequest(
        ContractHttpClientTlsPeerPemRequest(
            request.leafPem,
            ContractHttpClientTlsTrustRequest(
                request.trust.trustAnchorsPemBundle,
                intermediatesPemBundle: request.trust.intermediatesPemBundle,
                hostname: request.trust.hostname,
                validationTime: request.trust.validationTime,
                pinPolicy: request.trust.pinPolicy,
                policy: request.trust.policy
            )
        )
    )
}

public func bridgeVerifyHttpClientPeerCertificateChainPemRequest(
    request: BridgeHttpClientTlsPeerChainRequest
): ContractX509VerifyResult {
    contractVerifyHttpClientPeerCertificateChainPemRequest(
        ContractHttpClientTlsPeerChainRequest(
            request.certificateChainPemBundle,
            ContractHttpClientTlsTrustRequest(
                request.trust.trustAnchorsPemBundle,
                intermediatesPemBundle: request.trust.intermediatesPemBundle,
                hostname: request.trust.hostname,
                validationTime: request.trust.validationTime,
                pinPolicy: request.trust.pinPolicy,
                policy: request.trust.policy
            )
        )
    )
}

public func bridgeTryVerifyHttpClientPeerCertificateChainPemRequest(
    request: BridgeHttpClientTlsPeerChainRequest
): ContractX509VerifyOutcome {
    contractTryVerifyHttpClientPeerCertificateChainPemRequest(
        ContractHttpClientTlsPeerChainRequest(
            request.certificateChainPemBundle,
            ContractHttpClientTlsTrustRequest(
                request.trust.trustAnchorsPemBundle,
                intermediatesPemBundle: request.trust.intermediatesPemBundle,
                hostname: request.trust.hostname,
                validationTime: request.trust.validationTime,
                pinPolicy: request.trust.pinPolicy,
                policy: request.trust.policy
            )
        )
    )
}

public func bridgeTls12BuildHttpClientHello(
    keyExchange: ContractTls12KeyExchange,
    sessionId!: Array<Byte> = [],
    serverName!: String = "",
    alpnProtocols!: Array<String> = [],
    requestOcspStapling!: Bool = false
): ContractTls12ClientHello {
    contractTls12BuildHttpClientHello(
        keyExchange,
        sessionId: sessionId,
        serverName: serverName,
        alpnProtocols: alpnProtocols,
        requestOcspStapling: requestOcspStapling
    )
}

public func bridgeTls12BuildHttpClientHelloRequest(
    request: BridgeTls12HttpClientHelloRequest
): ContractTls12ClientHello {
    contractTls12BuildHttpClientHelloRequest(
        ContractTls12HttpClientHelloRequest(
            request.keyExchange,
            sessionId: request.sessionId,
            serverName: request.serverName,
            alpnProtocols: request.alpnProtocols,
            requestOcspStapling: request.requestOcspStapling
        )
    )
}

public func bridgeTls12BuildHttpServerHello(
    encodedClientHello: Array<Byte>,
    keyExchange: ContractTls12KeyExchange
): ContractTls12ServerHello {
    contractTls12BuildHttpServerHello(encodedClientHello, keyExchange)
}

public func bridgeTls12BuildHttpServerHelloRequest(
    request: BridgeTls12HttpServerHelloRequest
): ContractTls12ServerHello {
    contractTls12BuildHttpServerHelloRequest(
        ContractTls12HttpServerHelloRequest(
            request.encodedClientHello,
            request.keyExchange
        )
    )
}

public func bridgeTls12BuildCertificateHandshakeFromPemChain(
    certChainPemBundle: String
): Array<Byte> {
    contractTls12BuildCertificateHandshakeFromPemChain(certChainPemBundle)
}

public func bridgeTls12BuildCertificateHandshakeFromPemChainRequest(
    request: BridgeTls12CertificateHandshakeFromPemChainRequest
): Array<Byte> {
    contractTls12BuildCertificateHandshakeFromPemChainRequest(
        ContractTls12CertificateHandshakeFromPemChainRequest(request.certChainPemBundle)
    )
}

public func bridgeTls12VerifyCertificateHandshakeForHttp(
    encodedCertificateHandshake: Array<Byte>,
    trustAnchorsPemBundle: String,
    intermediatesPemBundle!: String = "",
    hostname!: String = "",
    validationTime!: String = "",
    pinPolicy!: ContractX509PinPolicy = ContractX509PinPolicy()
): ContractX509VerifyResult {
    contractTls12VerifyCertificateHandshakeForHttp(
        encodedCertificateHandshake,
        trustAnchorsPemBundle,
        intermediatesPemBundle: intermediatesPemBundle,
        hostname: hostname,
        validationTime: validationTime,
        pinPolicy: pinPolicy
    )
}

public func bridgeTls12VerifyCertificateHandshakeForHttpRequest(
    request: BridgeTls12VerifyCertificateHandshakeForHttpRequest
): ContractX509VerifyResult {
    contractTls12VerifyCertificateHandshakeForHttpRequest(
        ContractTls12VerifyCertificateHandshakeForHttpRequest(
            request.encodedCertificateHandshake,
            ContractHttpClientTlsTrustRequest(
                request.trust.trustAnchorsPemBundle,
                intermediatesPemBundle: request.trust.intermediatesPemBundle,
                hostname: request.trust.hostname,
                validationTime: request.trust.validationTime,
                pinPolicy: request.trust.pinPolicy,
                policy: request.trust.policy
            )
        )
    )
}

public func bridgeTls12BuildRsaClientKeyExchangeFromLeafPem(
    serverLeafPem: String
): ContractTls12RsaClientKeyExchange {
    contractTls12BuildRsaClientKeyExchangeFromLeafPem(serverLeafPem)
}

public func bridgeTls12BuildRsaClientKeyExchangeFromLeafPemRequest(
    request: BridgeTls12RsaClientKeyExchangeFromLeafPemRequest
): ContractTls12RsaClientKeyExchange {
    contractTls12BuildRsaClientKeyExchangeFromLeafPemRequest(
        ContractTls12RsaClientKeyExchangeFromLeafPemRequest(request.serverLeafPem)
    )
}

public func bridgeTls12ProcessRsaClientKeyExchange(
    serverPrivateKeyPkcs8Pem: String,
    encodedClientKeyExchange: Array<Byte>
): Array<Byte> {
    contractTls12ProcessRsaClientKeyExchange(serverPrivateKeyPkcs8Pem, encodedClientKeyExchange)
}

public func bridgeTls12ProcessRsaClientKeyExchangeRequest(
    request: BridgeTls12ProcessRsaClientKeyExchangeRequest
): Array<Byte> {
    contractTls12ProcessRsaClientKeyExchangeRequest(
        ContractTls12ProcessRsaClientKeyExchangeRequest(
            request.serverPrivateKeyPkcs8Pem,
            request.encodedClientKeyExchange
        )
    )
}

public func bridgeTls12DeriveSecretsFromPreMaster(
    preMasterSecret: Array<Byte>,
    clientRandom: Array<Byte>,
    serverRandom: Array<Byte>,
    keyLen!: Int64 = 16,
    ivLen!: Int64 = 12
): ContractTls12HandshakeSecrets {
    contractTls12DeriveSecretsFromPreMaster(
        preMasterSecret,
        clientRandom,
        serverRandom,
        keyLen: keyLen,
        ivLen: ivLen
    )
}

public func bridgeTls12DeriveSecretsFromPreMasterRequest(
    request: BridgeTls12DeriveSecretsFromPreMasterRequest
): ContractTls12HandshakeSecrets {
    contractTls12DeriveSecretsFromPreMasterRequest(
        ContractTls12DeriveSecretsFromPreMasterRequest(
            request.preMasterSecret,
            request.clientRandom,
            request.serverRandom,
            keyLen: request.keyLen,
            ivLen: request.ivLen
        )
    )
}

public func bridgeTls12BuildEcdheServerKeyExchange(
    keyExchange: ContractTls12KeyExchange,
    serverPrivateScalar!: ?Array<Byte> = None
): ContractTls12EcdheServerKeyExchange {
    contractTls12BuildEcdheServerKeyExchange(
        keyExchange,
        serverPrivateScalar: serverPrivateScalar
    )
}

public func bridgeTls12BuildEcdheServerKeyExchangeRequest(
    request: BridgeTls12EcdheServerKeyExchangeRequest
): ContractTls12EcdheServerKeyExchange {
    contractTls12BuildEcdheServerKeyExchangeRequest(
        ContractTls12EcdheServerKeyExchangeRequest(
            request.keyExchange,
            serverPrivateScalar: request.serverPrivateScalar
        )
    )
}

public func bridgeTls12BuildEcdheClientKeyExchange(
    keyExchange: ContractTls12KeyExchange,
    clientPrivateScalar!: ?Array<Byte> = None
): ContractTls12EcdheClientKeyExchange {
    contractTls12BuildEcdheClientKeyExchange(
        keyExchange,
        clientPrivateScalar: clientPrivateScalar
    )
}

public func bridgeTls12BuildEcdheClientKeyExchangeRequest(
    request: BridgeTls12EcdheClientKeyExchangeRequest
): ContractTls12EcdheClientKeyExchange {
    contractTls12BuildEcdheClientKeyExchangeRequest(
        ContractTls12EcdheClientKeyExchangeRequest(
            request.keyExchange,
            clientPrivateScalar: request.clientPrivateScalar
        )
    )
}

public func bridgeTls12DeriveClientSecretsFromEcdhe(
    keyExchange: ContractTls12KeyExchange,
    clientPrivateScalar: Array<Byte>,
    encodedServerKeyExchange: Array<Byte>,
    clientRandom: Array<Byte>,
    serverRandom: Array<Byte>,
    keyLen!: Int64 = 16,
    ivLen!: Int64 = 12
): ContractTls12HandshakeSecrets {
    contractTls12DeriveClientSecretsFromEcdhe(
        keyExchange,
        clientPrivateScalar,
        encodedServerKeyExchange,
        clientRandom,
        serverRandom,
        keyLen: keyLen,
        ivLen: ivLen
    )
}

public func bridgeTls12DeriveClientSecretsFromEcdheRequest(
    request: BridgeTls12DeriveClientSecretsFromEcdheRequest
): ContractTls12HandshakeSecrets {
    contractTls12DeriveClientSecretsFromEcdheRequest(
        ContractTls12DeriveClientSecretsFromEcdheRequest(
            request.keyExchange,
            request.clientPrivateScalar,
            request.encodedServerKeyExchange,
            request.clientRandom,
            request.serverRandom,
            keyLen: request.keyLen,
            ivLen: request.ivLen
        )
    )
}

public func bridgeTls12DeriveServerSecretsFromEcdhe(
    keyExchange: ContractTls12KeyExchange,
    serverPrivateScalar: Array<Byte>,
    encodedClientKeyExchange: Array<Byte>,
    clientRandom: Array<Byte>,
    serverRandom: Array<Byte>,
    keyLen!: Int64 = 16,
    ivLen!: Int64 = 12
): ContractTls12HandshakeSecrets {
    contractTls12DeriveServerSecretsFromEcdhe(
        keyExchange,
        serverPrivateScalar,
        encodedClientKeyExchange,
        clientRandom,
        serverRandom,
        keyLen: keyLen,
        ivLen: ivLen
    )
}

public func bridgeTls12DeriveServerSecretsFromEcdheRequest(
    request: BridgeTls12DeriveServerSecretsFromEcdheRequest
): ContractTls12HandshakeSecrets {
    contractTls12DeriveServerSecretsFromEcdheRequest(
        ContractTls12DeriveServerSecretsFromEcdheRequest(
            request.keyExchange,
            request.serverPrivateScalar,
            request.encodedClientKeyExchange,
            request.clientRandom,
            request.serverRandom,
            keyLen: request.keyLen,
            ivLen: request.ivLen
        )
    )
}

public func bridgeTls12CreateClientRecordChannel(
    secrets: ContractTls12HandshakeSecrets,
    algorithm!: ContractAeadAlgorithm = ContractAeadAlgorithm.Aes256Gcm
): ContractTlsRecordChannel {
    contractTls12CreateClientRecordChannel(
        secrets,
        algorithm: algorithm
    )
}

public func bridgeTls12CreateClientRecordChannelRequest(
    request: BridgeTls12RecordChannelRequest
): ContractTlsRecordChannel {
    contractTls12CreateClientRecordChannelRequest(
        ContractTls12RecordChannelRequest(
            request.secrets,
            algorithm: request.algorithm
        )
    )
}

public func bridgeTls12CreateServerRecordChannel(
    secrets: ContractTls12HandshakeSecrets,
    algorithm!: ContractAeadAlgorithm = ContractAeadAlgorithm.Aes256Gcm
): ContractTlsRecordChannel {
    contractTls12CreateServerRecordChannel(
        secrets,
        algorithm: algorithm
    )
}

public func bridgeTls12CreateServerRecordChannelRequest(
    request: BridgeTls12RecordChannelRequest
): ContractTlsRecordChannel {
    contractTls12CreateServerRecordChannelRequest(
        ContractTls12RecordChannelRequest(
            request.secrets,
            algorithm: request.algorithm
        )
    )
}

public func bridgeTls13BuildHttpClientHelloX25519(
    serverName: String,
    alpnProtocols!: Array<String> = [],
    clientPrivateKey!: ?Array<Byte> = None
): ContractTls13HttpClientHelloX25519 {
    contractTls13BuildHttpClientHelloX25519(
        serverName,
        alpnProtocols: alpnProtocols,
        clientPrivateKey: clientPrivateKey
    )
}

public func bridgeTls13BuildHttpClientHelloX25519Request(
    request: BridgeTls13HttpClientHelloX25519Request
): ContractTls13HttpClientHelloX25519 {
    contractTls13BuildHttpClientHelloX25519Request(
        ContractTls13HttpClientHelloX25519Request(
            request.serverName,
            alpnProtocols: request.alpnProtocols,
            clientPrivateKey: request.clientPrivateKey
        )
    )
}

public func bridgeTls13BuildHttpServerFlightX25519(
    encodedClientHello: Array<Byte>,
    serverKeyExchangePrivate: Array<Byte>,
    certChainPemBundle: String,
    certificatePrivateKeyPkcs8Pem: String,
    policy!: ContractTlsHttpNegotiationPolicy = ContractTlsHttpNegotiationPolicy()
): ContractTls13HttpServerFlight {
    contractTls13BuildHttpServerFlightX25519(
        encodedClientHello,
        serverKeyExchangePrivate,
        certChainPemBundle,
        certificatePrivateKeyPkcs8Pem,
        policy: policy
    )
}

public func bridgeTls13BuildHttpServerFlightX25519Request(
    request: BridgeTls13HttpServerFlightX25519Request
): ContractTls13HttpServerFlight {
    contractTls13BuildHttpServerFlightX25519Request(
        ContractTls13HttpServerFlightX25519Request(
            request.encodedClientHello,
            request.serverKeyExchangePrivate,
            request.certChainPemBundle,
            request.certificatePrivateKeyPkcs8Pem,
            policy: request.policy
        )
    )
}

public func bridgeBuildHttpServerAttachResultFromTls13Flight(
    serverFlight: ContractTls13HttpServerFlight
): ContractHttpServerAttachResult {
    contractBuildHttpServerAttachResultFromTls13Flight(serverFlight)
}

public func bridgeTls13BuildHttpServerFlightX25519Rsa(
    encodedClientHello: Array<Byte>,
    serverKeyExchangePrivate: Array<Byte>,
    certChainPemBundle: String,
    certificatePrivateKeyPkcs8Pem: String,
    policy!: ContractTlsHttpNegotiationPolicy = ContractTlsHttpNegotiationPolicy()
): ContractTls13HttpServerFlight {
    contractTls13BuildHttpServerFlightX25519Rsa(
        encodedClientHello,
        serverKeyExchangePrivate,
        certChainPemBundle,
        certificatePrivateKeyPkcs8Pem,
        policy: policy
    )
}

public func bridgeTls13BuildHttpServerFlightX25519RsaRequest(
    request: BridgeTls13HttpServerFlightX25519Request
): ContractTls13HttpServerFlight {
    contractTls13BuildHttpServerFlightX25519Request(
        ContractTls13HttpServerFlightX25519Request(
            request.encodedClientHello,
            request.serverKeyExchangePrivate,
            request.certChainPemBundle,
            request.certificatePrivateKeyPkcs8Pem,
            policy: request.policy
        )
    )
}

public func bridgeTls13VerifyHttpServerFlightX25519(
    clientHello: ContractTls13HttpClientHelloX25519,
    serverFlight: ContractTls13HttpServerFlight,
    trustAnchorsPemBundle: String,
    intermediatesPemBundle!: String = "",
    hostname!: String = "",
    validationTime!: String = "",
    pinPolicy!: ContractX509PinPolicy = ContractX509PinPolicy(),
    policy!: ContractTlsHttpNegotiationPolicy = ContractTlsHttpNegotiationPolicy()
): ContractTls13HttpClientResult {
    contractTls13VerifyHttpServerFlightX25519(
        clientHello,
        serverFlight,
        trustAnchorsPemBundle,
        intermediatesPemBundle: intermediatesPemBundle,
        hostname: hostname,
        validationTime: validationTime,
        pinPolicy: pinPolicy,
        policy: policy
    )
}

public func bridgeTls13VerifyHttpServerFlightX25519Request(
    request: BridgeTls13HttpVerifyServerFlightX25519Request
): ContractTls13HttpClientResult {
    contractTls13VerifyHttpServerFlightX25519Request(
        ContractTls13HttpVerifyServerFlightX25519Request(
            request.clientHello,
            request.serverFlight,
            ContractHttpClientTlsTrustRequest(
                request.trust.trustAnchorsPemBundle,
                intermediatesPemBundle: request.trust.intermediatesPemBundle,
                hostname: request.trust.hostname,
                validationTime: request.trust.validationTime,
                pinPolicy: request.trust.pinPolicy,
                policy: request.trust.policy
            )
        )
    )
}

public func bridgeTls13VerifyHttpServerFlightX25519WithSession(
    clientHello: ContractTls13HttpClientHelloX25519,
    serverFlight: ContractTls13HttpServerFlight,
    trustAnchorsPemBundle: String,
    intermediatesPemBundle!: String = "",
    hostname!: String = "",
    validationTime!: String = "",
    pinPolicy!: ContractX509PinPolicy = ContractX509PinPolicy(),
    policy!: ContractTlsHttpNegotiationPolicy = ContractTlsHttpNegotiationPolicy()
): ContractTls13HttpClientVerifiedSession {
    contractTls13VerifyHttpServerFlightX25519WithSession(
        clientHello,
        serverFlight,
        trustAnchorsPemBundle,
        intermediatesPemBundle: intermediatesPemBundle,
        hostname: hostname,
        validationTime: validationTime,
        pinPolicy: pinPolicy,
        policy: policy
    )
}

public func bridgeTls13VerifyHttpServerFlightX25519WithSessionRequest(
    request: BridgeTls13HttpVerifyServerFlightX25519Request
): ContractTls13HttpClientVerifiedSession {
    contractTls13VerifyHttpServerFlightX25519WithSessionRequest(
        ContractTls13HttpVerifyServerFlightX25519Request(
            request.clientHello,
            request.serverFlight,
            ContractHttpClientTlsTrustRequest(
                request.trust.trustAnchorsPemBundle,
                intermediatesPemBundle: request.trust.intermediatesPemBundle,
                hostname: request.trust.hostname,
                validationTime: request.trust.validationTime,
                pinPolicy: request.trust.pinPolicy,
                policy: request.trust.policy
            )
        )
    )
}

public func bridgeTryTls13VerifyHttpServerFlightX25519(
    clientHello: ContractTls13HttpClientHelloX25519,
    serverFlight: ContractTls13HttpServerFlight,
    trustAnchorsPemBundle: String,
    intermediatesPemBundle!: String = "",
    hostname!: String = "",
    validationTime!: String = "",
    pinPolicy!: ContractX509PinPolicy = ContractX509PinPolicy(),
    policy!: ContractTlsHttpNegotiationPolicy = ContractTlsHttpNegotiationPolicy()
): ContractTls13HttpClientVerifyOutcome {
    contractTryTls13VerifyHttpServerFlightX25519(
        clientHello,
        serverFlight,
        trustAnchorsPemBundle,
        intermediatesPemBundle: intermediatesPemBundle,
        hostname: hostname,
        validationTime: validationTime,
        pinPolicy: pinPolicy,
        policy: policy
    )
}

public func bridgeTryTls13VerifyHttpServerFlightX25519Request(
    request: BridgeTls13HttpVerifyServerFlightX25519Request
): ContractTls13HttpClientVerifyOutcome {
    contractTryTls13VerifyHttpServerFlightX25519Request(
        ContractTls13HttpVerifyServerFlightX25519Request(
            request.clientHello,
            request.serverFlight,
            ContractHttpClientTlsTrustRequest(
                request.trust.trustAnchorsPemBundle,
                intermediatesPemBundle: request.trust.intermediatesPemBundle,
                hostname: request.trust.hostname,
                validationTime: request.trust.validationTime,
                pinPolicy: request.trust.pinPolicy,
                policy: request.trust.policy
            )
        )
    )
}

public func bridgeTryTls13VerifyHttpServerFlightX25519WithSession(
    clientHello: ContractTls13HttpClientHelloX25519,
    serverFlight: ContractTls13HttpServerFlight,
    trustAnchorsPemBundle: String,
    intermediatesPemBundle!: String = "",
    hostname!: String = "",
    validationTime!: String = "",
    pinPolicy!: ContractX509PinPolicy = ContractX509PinPolicy(),
    policy!: ContractTlsHttpNegotiationPolicy = ContractTlsHttpNegotiationPolicy()
): ContractTls13HttpClientVerifiedSessionOutcome {
    contractTryTls13VerifyHttpServerFlightX25519WithSession(
        clientHello,
        serverFlight,
        trustAnchorsPemBundle,
        intermediatesPemBundle: intermediatesPemBundle,
        hostname: hostname,
        validationTime: validationTime,
        pinPolicy: pinPolicy,
        policy: policy
    )
}

public func bridgeTryTls13VerifyHttpServerFlightX25519WithSessionRequest(
    request: BridgeTls13HttpVerifyServerFlightX25519Request
): ContractTls13HttpClientVerifiedSessionOutcome {
    contractTryTls13VerifyHttpServerFlightX25519WithSessionRequest(
        ContractTls13HttpVerifyServerFlightX25519Request(
            request.clientHello,
            request.serverFlight,
            ContractHttpClientTlsTrustRequest(
                request.trust.trustAnchorsPemBundle,
                intermediatesPemBundle: request.trust.intermediatesPemBundle,
                hostname: request.trust.hostname,
                validationTime: request.trust.validationTime,
                pinPolicy: request.trust.pinPolicy,
                policy: request.trust.policy
            )
        )
    )
}

public func bridgeTls13DeriveExporterMasterSecret(
    masterSecret: Array<Byte>,
    transcriptHash: Array<Byte>
): Array<Byte> {
    contractTls13DeriveExporterMasterSecret(masterSecret, transcriptHash)
}

public func bridgeTls13DeriveNextApplicationTrafficSecret(
    currentTrafficSecret: Array<Byte>
): Array<Byte> {
    contractTls13DeriveNextApplicationTrafficSecret(currentTrafficSecret)
}

public func bridgeTls13DeriveApplicationTrafficKeyIv(
    applicationTrafficSecret: Array<Byte>,
    keyLen!: Int64 = 16,
    ivLen!: Int64 = 12
): (Array<Byte>, Array<Byte>) {
    contractTls13DeriveApplicationTrafficKeyIv(
        applicationTrafficSecret,
        keyLen: keyLen,
        ivLen: ivLen
    )
}

public func bridgeTls13DeriveExporterMasterSecretRequest(
    request: BridgeTls13ExporterMasterSecretRequest
): Array<Byte> {
    contractTls13DeriveExporterMasterSecretRequest(
        ContractTls13ExporterMasterSecretRequest(
            request.masterSecret,
            request.transcriptHash
        )
    )
}

public func bridgeTls13ExportKeyingMaterial(
    exporterMasterSecret: Array<Byte>,
    exporterLabel: String,
    context!: Array<Byte> = [],
    outputLen!: Int64 = 32
): Array<Byte> {
    contractTls13ExportKeyingMaterial(
        exporterMasterSecret,
        exporterLabel,
        context: context,
        outputLen: outputLen
    )
}

public func bridgeTls13ExportKeyingMaterialRequest(
    request: BridgeTls13ExportKeyingMaterialRequest
): Array<Byte> {
    contractTls13ExportKeyingMaterialRequest(
        ContractTls13ExportKeyingMaterialRequest(
            request.exporterMasterSecret,
            request.exporterLabel,
            context: request.context,
            outputLen: request.outputLen
        )
    )
}

public func bridgeTls13ExportHttpVerifiedSessionKeyingMaterial(
    verifiedSession: ContractTls13HttpClientVerifiedSession,
    exporterLabel: String,
    context!: Array<Byte> = [],
    outputLen!: Int64 = 32
): Array<Byte> {
    let exporterMaster = contractTls13DeriveExporterMasterSecret(
        verifiedSession.masterSecret,
        verifiedSession.transcriptHash
    )
    contractTls13ExportKeyingMaterial(
        exporterMaster,
        exporterLabel,
        context: context,
        outputLen: outputLen
    )
}

public func bridgeTls13CreateClientRecordChannel(
    keyMaterial: ContractTls13ApplicationKeyMaterial,
    algorithm!: ContractAeadAlgorithm = ContractAeadAlgorithm.Aes256Gcm
): ContractTlsRecordChannel {
    contractTls13CreateClientRecordChannel(
        keyMaterial,
        algorithm: algorithm
    )
}

public func bridgeTls13CreateClientRecordChannelRequest(
    request: BridgeTls13RecordChannelRequest
): ContractTlsRecordChannel {
    contractTls13CreateClientRecordChannelRequest(
        ContractTls13RecordChannelRequest(
            request.keyMaterial,
            algorithm: request.algorithm
        )
    )
}

public func bridgeTls13CreateServerRecordChannel(
    keyMaterial: ContractTls13ApplicationKeyMaterial,
    algorithm!: ContractAeadAlgorithm = ContractAeadAlgorithm.Aes256Gcm
): ContractTlsRecordChannel {
    contractTls13CreateServerRecordChannel(
        keyMaterial,
        algorithm: algorithm
    )
}

public func bridgeTls13CreateServerRecordChannelRequest(
    request: BridgeTls13RecordChannelRequest
): ContractTlsRecordChannel {
    contractTls13CreateServerRecordChannelRequest(
        ContractTls13RecordChannelRequest(
            request.keyMaterial,
            algorithm: request.algorithm
        )
    )
}

public func bridgeTls13BuildKeyUpdateHandshake(
    requestPeerUpdate!: Bool = false
): Array<Byte> {
    contractTls13BuildKeyUpdateHandshake(requestPeerUpdate: requestPeerUpdate)
}

public func bridgeTls13BuildKeyUpdateHandshakeRequest(
    request: BridgeTls13KeyUpdateHandshakeRequest
): Array<Byte> {
    contractTls13BuildKeyUpdateHandshake(requestPeerUpdate: request.requestPeerUpdate)
}

public func bridgeTls13DecodeKeyUpdateHandshake(encodedKeyUpdate: Array<Byte>): Bool {
    contractTls13DecodeKeyUpdateHandshake(encodedKeyUpdate)
}

public func bridgeTls13DecodeKeyUpdateHandshakeRequest(
    request: BridgeTls13KeyUpdateHandshakeDecodeRequest
): Bool {
    contractTls13DecodeKeyUpdateHandshake(request.encodedKeyUpdate)
}

public func bridgeTls13PrepareKeyUpdate(
    currentTrafficSecret: Array<Byte>,
    requestPeerUpdate!: Bool = false,
    keyLen!: Int64 = 16,
    ivLen!: Int64 = 12
): ContractTls13KeyUpdatePlan {
    contractTls13PrepareKeyUpdate(
        currentTrafficSecret,
        requestPeerUpdate: requestPeerUpdate,
        keyLen: keyLen,
        ivLen: ivLen
    )
}

public func bridgeTls13PrepareKeyUpdateRequest(
    request: BridgeTls13KeyUpdateRequest
): ContractTls13KeyUpdatePlan {
    contractTls13PrepareKeyUpdateRequest(
        ContractTls13KeyUpdateRequest(
            request.currentTrafficSecret,
            requestPeerUpdate: request.requestPeerUpdate,
            keyLen: request.keyLen,
            ivLen: request.ivLen
        )
    )
}

public func bridgeTls13ApplyPeerKeyUpdate(
    currentTrafficSecret: Array<Byte>,
    encodedKeyUpdate: Array<Byte>,
    keyLen!: Int64 = 16,
    ivLen!: Int64 = 12
): ContractTls13KeyUpdatePlan {
    contractTls13ApplyPeerKeyUpdate(
        currentTrafficSecret,
        encodedKeyUpdate,
        keyLen: keyLen,
        ivLen: ivLen
    )
}

public func bridgeTls13ApplyPeerKeyUpdateRequest(
    request: BridgeTls13PeerKeyUpdateRequest
): ContractTls13KeyUpdatePlan {
    contractTls13ApplyPeerKeyUpdateRequest(
        ContractTls13PeerKeyUpdateRequest(
            request.currentTrafficSecret,
            request.encodedKeyUpdate,
            keyLen: request.keyLen,
            ivLen: request.ivLen
        )
    )
}

public func bridgeTls13ResolveCipherBindingFromVerifiedSession(
    session: ContractTls13HttpClientVerifiedSession
): ContractTls13CipherBinding {
    contractTls13ResolveCipherBindingFromVerifiedSession(session)
}

public func bridgeTls13ResolveCipherBinding(cipherSuite: Int64): ContractTls13CipherBinding {
    contractTls13ResolveCipherBinding(cipherSuite)
}

public func bridgeTls13ResolveCipherBindingRequest(
    request: BridgeTls13CipherBindingRequest
): ContractTls13CipherBinding {
    contractTls13ResolveCipherBinding(request.cipherSuite)
}

public func bridgeTls13ResolveCipherBindingFromServerHello(
    encodedServerHello: Array<Byte>
): ContractTls13CipherBinding {
    contractTls13ResolveCipherBindingFromServerHello(encodedServerHello)
}

public func bridgeTls13ResolveCipherBindingFromServerHelloRequest(
    request: BridgeTls13CipherBindingFromServerHelloRequest
): ContractTls13CipherBinding {
    contractTls13ResolveCipherBindingFromServerHello(request.encodedServerHello)
}

public func bridgeTls13ResolveCipherBindingFromServerFlight(
    serverFlight: ContractTls13HttpServerFlight
): ContractTls13CipherBinding {
    contractTls13ResolveCipherBindingFromServerFlight(serverFlight)
}

public func bridgeTls13ResolveCipherBindingFromServerFlightRequest(
    request: BridgeTls13CipherBindingFromServerFlightRequest
): ContractTls13CipherBinding {
    contractTls13ResolveCipherBindingFromServerFlight(request.serverFlight)
}

public func bridgeTls13DerivePskX25519SecretsForCipherSuite(
    psk: Array<Byte>,
    clientPrivateKey: Array<Byte>,
    serverPublicKey: Array<Byte>,
    transcriptHash: Array<Byte>,
    cipherSuite: Int64
): ContractTls13PskX25519DerivedSecrets {
    contractTls13DerivePskX25519SecretsForCipherSuite(
        psk,
        clientPrivateKey,
        serverPublicKey,
        transcriptHash,
        cipherSuite
    )
}

public func bridgeTls13DerivePskX25519SecretsFromSessionTicketForCipherSuite(
    ticket: ContractTlsSessionTicket,
    clientPrivateKey: Array<Byte>,
    serverPublicKey: Array<Byte>,
    transcriptHash: Array<Byte>,
    cipherSuite: Int64
): ContractTls13PskX25519DerivedSecrets {
    contractTls13DerivePskX25519SecretsFromSessionTicketForCipherSuite(
        ticket,
        clientPrivateKey,
        serverPublicKey,
        transcriptHash,
        cipherSuite
    )
}

public func bridgeTls13DerivePskX25519SecretsFromSessionTicketAndServerHello(
    ticket: ContractTlsSessionTicket,
    clientPrivateKey: Array<Byte>,
    serverPublicKey: Array<Byte>,
    transcriptHash: Array<Byte>,
    encodedServerHello: Array<Byte>
): ContractTls13PskX25519DerivedSecrets {
    contractTls13DerivePskX25519SecretsFromSessionTicketAndServerHello(
        ticket,
        clientPrivateKey,
        serverPublicKey,
        transcriptHash,
        encodedServerHello
    )
}

public func bridgeTls13CreateClientRecordChannelFromPskX25519Secrets(
    secrets: ContractTls13PskX25519DerivedSecrets
): ContractTlsRecordChannel {
    contractTls13CreateClientRecordChannelFromPskX25519Secrets(secrets)
}

public func bridgeTls13CreateServerRecordChannelFromPskX25519Secrets(
    secrets: ContractTls13PskX25519DerivedSecrets
): ContractTlsRecordChannel {
    contractTls13CreateServerRecordChannelFromPskX25519Secrets(secrets)
}

public func bridgeTls13CreatePskX25519ChannelSetFromSecrets(
    secrets: ContractTls13PskX25519DerivedSecrets
): ContractTls13PskX25519ChannelSet {
    contractTls13CreatePskX25519ChannelSetFromSecrets(secrets)
}

public func bridgeTls13CreatePskX25519ChannelSetFromSessionTicketAndServerHello(
    ticket: ContractTlsSessionTicket,
    clientPrivateKey: Array<Byte>,
    serverPublicKey: Array<Byte>,
    transcriptHash: Array<Byte>,
    encodedServerHello: Array<Byte>
): ContractTls13PskX25519ChannelSet {
    contractTls13CreatePskX25519ChannelSetFromSessionTicketAndServerHello(
        ticket,
        clientPrivateKey,
        serverPublicKey,
        transcriptHash,
        encodedServerHello
    )
}

public func bridgeTls13RotatePskX25519ClientTraffic(
    channels: ContractTls13PskX25519ChannelSet,
    requestPeerUpdate!: Bool = false
): ContractTls13PskX25519TrafficUpdateResult {
    contractTls13RotatePskX25519ClientTraffic(
        channels,
        requestPeerUpdate: requestPeerUpdate
    )
}

public func bridgeTls13RotatePskX25519ServerTraffic(
    channels: ContractTls13PskX25519ChannelSet,
    requestPeerUpdate!: Bool = false
): ContractTls13PskX25519TrafficUpdateResult {
    contractTls13RotatePskX25519ServerTraffic(
        channels,
        requestPeerUpdate: requestPeerUpdate
    )
}

public func bridgeTls13ApplyPskX25519ClientTrafficUpdate(
    channels: ContractTls13PskX25519ChannelSet,
    encodedKeyUpdate: Array<Byte>
): ContractTls13PskX25519TrafficUpdateResult {
    contractTls13ApplyPskX25519ClientTrafficUpdate(
        channels,
        encodedKeyUpdate
    )
}

public func bridgeTls13ApplyPskX25519ServerTrafficUpdate(
    channels: ContractTls13PskX25519ChannelSet,
    encodedKeyUpdate: Array<Byte>
): ContractTls13PskX25519TrafficUpdateResult {
    contractTls13ApplyPskX25519ServerTrafficUpdate(
        channels,
        encodedKeyUpdate
    )
}

public func bridgeTls13ApplyPskX25519ClientTrafficUpdateAndMaybeRespond(
    channels: ContractTls13PskX25519ChannelSet,
    encodedKeyUpdate: Array<Byte>,
    forceResponse!: Bool = false
): ContractTls13PskX25519PeerUpdateOrchestrationResult {
    contractTls13ApplyPskX25519ClientTrafficUpdateAndMaybeRespond(
        channels,
        encodedKeyUpdate,
        forceResponse: forceResponse
    )
}

public func bridgeTls13ApplyPskX25519ServerTrafficUpdateAndMaybeRespond(
    channels: ContractTls13PskX25519ChannelSet,
    encodedKeyUpdate: Array<Byte>,
    forceResponse!: Bool = false
): ContractTls13PskX25519PeerUpdateOrchestrationResult {
    contractTls13ApplyPskX25519ServerTrafficUpdateAndMaybeRespond(
        channels,
        encodedKeyUpdate,
        forceResponse: forceResponse
    )
}

public func bridgeTls13RotatePskX25519LocalTraffic(
    channels: ContractTls13PskX25519ChannelSet,
    localEndpointRole: ContractTlsEndpointRole,
    requestPeerUpdate!: Bool = false
): ContractTls13PskX25519TrafficUpdateResult {
    contractTls13RotatePskX25519LocalTraffic(
        channels,
        localEndpointRole,
        requestPeerUpdate: requestPeerUpdate
    )
}

public func bridgeTls13ApplyPskX25519PeerTrafficUpdate(
    channels: ContractTls13PskX25519ChannelSet,
    encodedKeyUpdate: Array<Byte>,
    localEndpointRole: ContractTlsEndpointRole
): ContractTls13PskX25519TrafficUpdateResult {
    contractTls13ApplyPskX25519PeerTrafficUpdate(
        channels,
        encodedKeyUpdate,
        localEndpointRole
    )
}

public func bridgeTls13ApplyPskX25519PeerTrafficUpdateAndMaybeRespond(
    channels: ContractTls13PskX25519ChannelSet,
    encodedKeyUpdate: Array<Byte>,
    localEndpointRole: ContractTlsEndpointRole,
    forceResponse!: Bool = false
): ContractTls13PskX25519PeerUpdateOrchestrationResult {
    contractTls13ApplyPskX25519PeerTrafficUpdateAndMaybeRespond(
        channels,
        encodedKeyUpdate,
        localEndpointRole,
        forceResponse: forceResponse
    )
}

public func bridgeTls13CreateClientRecordChannelFromVerifiedSession(
    session: ContractTls13HttpClientVerifiedSession
): ContractTlsRecordChannel {
    contractTls13CreateClientRecordChannelFromVerifiedSession(session)
}

public func bridgeTls13CreateClientRecordChannelFromVerifiedSessionRequest(
    request: BridgeTls13HttpVerifiedSessionRequest
): ContractTlsRecordChannel {
    contractTls13CreateClientRecordChannelFromVerifiedSessionRequest(
        ContractTls13HttpVerifiedSessionRequest(request.session)
    )
}

public func bridgeTls13CreateServerRecordChannelFromVerifiedSession(
    session: ContractTls13HttpClientVerifiedSession
): ContractTlsRecordChannel {
    contractTls13CreateServerRecordChannelFromVerifiedSession(session)
}

public func bridgeTls13CreateServerRecordChannelFromVerifiedSessionRequest(
    request: BridgeTls13HttpVerifiedSessionRequest
): ContractTlsRecordChannel {
    contractTls13CreateServerRecordChannelFromVerifiedSessionRequest(
        ContractTls13HttpVerifiedSessionRequest(request.session)
    )
}

public func bridgeTls13CreateVerifiedSessionChannelSet(
    session: ContractTls13HttpClientVerifiedSession
): ContractTls13HttpVerifiedSessionChannelSet {
    contractTls13CreateVerifiedSessionChannelSet(session)
}

public func bridgeTls13CreateVerifiedSessionChannelSetRequest(
    request: BridgeTls13HttpVerifiedSessionRequest
): ContractTls13HttpVerifiedSessionChannelSet {
    contractTls13CreateVerifiedSessionChannelSetRequest(
        ContractTls13HttpVerifiedSessionRequest(request.session)
    )
}

public func bridgeTls13DeriveExporterMasterSecretFromVerifiedSession(
    session: ContractTls13HttpClientVerifiedSession
): Array<Byte> {
    contractTls13DeriveExporterMasterSecretFromVerifiedSession(session)
}

public func bridgeTls13DeriveExporterMasterSecretFromVerifiedSessionRequest(
    request: BridgeTls13HttpVerifiedSessionRequest
): Array<Byte> {
    contractTls13DeriveExporterMasterSecretFromVerifiedSessionRequest(
        ContractTls13HttpVerifiedSessionRequest(request.session)
    )
}

public func bridgeTls13ExportKeyingMaterialFromVerifiedSession(
    session: ContractTls13HttpClientVerifiedSession,
    exporterLabel: String,
    context!: Array<Byte> = [],
    outputLen!: Int64 = 32
): Array<Byte> {
    contractTls13ExportKeyingMaterialFromVerifiedSession(
        session,
        exporterLabel,
        context: context,
        outputLen: outputLen
    )
}

public func bridgeTls13ExportKeyingMaterialFromVerifiedSessionRequest(
    request: BridgeTls13HttpVerifiedSessionExportRequest
): Array<Byte> {
    contractTls13ExportKeyingMaterialFromVerifiedSessionRequest(
        ContractTls13HttpVerifiedSessionExportRequest(
            request.session,
            request.exporterLabel,
            context: request.context,
            outputLen: request.outputLen
        )
    )
}

public func bridgeTls13PrepareClientKeyUpdateFromVerifiedSession(
    verifiedSession: ContractTls13HttpClientVerifiedSession,
    requestPeerUpdate!: Bool = false
): ContractTls13KeyUpdatePlan {
    contractTls13PrepareKeyUpdate(
        verifiedSession.clientAppTrafficSecret,
        requestPeerUpdate: requestPeerUpdate,
        keyLen: verifiedSession.result.keyMaterial.clientWriteKey.size,
        ivLen: verifiedSession.result.keyMaterial.clientWriteIv.size
    )
}

public func bridgeTls13PrepareKeyUpdateFromVerifiedSession(
    session: ContractTls13HttpClientVerifiedSession,
    requestPeerUpdate!: Bool = false
): ContractTls13KeyUpdatePlan {
    contractTls13PrepareKeyUpdateFromVerifiedSession(
        session,
        requestPeerUpdate: requestPeerUpdate
    )
}

public func bridgeTls13PrepareKeyUpdateFromVerifiedSessionRequest(
    request: BridgeTls13HttpVerifiedSessionKeyUpdateRequest
): ContractTls13KeyUpdatePlan {
    contractTls13PrepareKeyUpdateFromVerifiedSessionRequest(
        ContractTls13HttpVerifiedSessionKeyUpdateRequest(
            request.session,
            requestPeerUpdate: request.requestPeerUpdate
        )
    )
}

public func bridgeTls13PrepareServerKeyUpdateFromVerifiedSession(
    verifiedSession: ContractTls13HttpClientVerifiedSession,
    requestPeerUpdate!: Bool = false
): ContractTls13KeyUpdatePlan {
    contractTls13PrepareKeyUpdate(
        verifiedSession.serverAppTrafficSecret,
        requestPeerUpdate: requestPeerUpdate,
        keyLen: verifiedSession.result.keyMaterial.serverWriteKey.size,
        ivLen: verifiedSession.result.keyMaterial.serverWriteIv.size
    )
}

public func bridgeTls13ApplyClientPeerKeyUpdateFromVerifiedSession(
    verifiedSession: ContractTls13HttpClientVerifiedSession,
    encodedKeyUpdate: Array<Byte>
): ContractTls13KeyUpdatePlan {
    contractTls13ApplyPeerKeyUpdate(
        verifiedSession.serverAppTrafficSecret,
        encodedKeyUpdate,
        keyLen: verifiedSession.result.keyMaterial.serverWriteKey.size,
        ivLen: verifiedSession.result.keyMaterial.serverWriteIv.size
    )
}

public func bridgeTls13ApplyPeerKeyUpdateFromVerifiedSession(
    session: ContractTls13HttpClientVerifiedSession,
    encodedKeyUpdate: Array<Byte>
): ContractTls13KeyUpdatePlan {
    contractTls13ApplyPeerKeyUpdateFromVerifiedSession(
        session,
        encodedKeyUpdate
    )
}

public func bridgeTls13ApplyPeerKeyUpdateFromVerifiedSessionRequest(
    request: BridgeTls13HttpVerifiedSessionPeerKeyUpdateRequest
): ContractTls13KeyUpdatePlan {
    contractTls13ApplyPeerKeyUpdateFromVerifiedSessionRequest(
        ContractTls13HttpVerifiedSessionPeerKeyUpdateRequest(
            request.session,
            request.encodedKeyUpdate
        )
    )
}

public func bridgeTls13ApplyServerPeerKeyUpdateFromVerifiedSession(
    verifiedSession: ContractTls13HttpClientVerifiedSession,
    encodedKeyUpdate: Array<Byte>
): ContractTls13KeyUpdatePlan {
    contractTls13ApplyPeerKeyUpdate(
        verifiedSession.clientAppTrafficSecret,
        encodedKeyUpdate,
        keyLen: verifiedSession.result.keyMaterial.clientWriteKey.size,
        ivLen: verifiedSession.result.keyMaterial.clientWriteIv.size
    )
}

public func bridgeTls13RotateClientTrafficInVerifiedSession(
    session: ContractTls13HttpClientVerifiedSession,
    requestPeerUpdate!: Bool = false
): ContractTls13HttpVerifiedSessionTrafficUpdateResult {
    contractTls13RotateClientTrafficInVerifiedSession(
        session,
        requestPeerUpdate: requestPeerUpdate
    )
}

public func bridgeTls13RotateClientTrafficInVerifiedSessionRequest(
    request: BridgeTls13HttpVerifiedSessionKeyUpdateRequest
): ContractTls13HttpVerifiedSessionTrafficUpdateResult {
    contractTls13RotateClientTrafficInVerifiedSessionRequest(
        ContractTls13HttpVerifiedSessionKeyUpdateRequest(
            request.session,
            requestPeerUpdate: request.requestPeerUpdate
        )
    )
}

public func bridgeTls13ApplyPeerTrafficUpdateToVerifiedSession(
    session: ContractTls13HttpClientVerifiedSession,
    encodedKeyUpdate: Array<Byte>
): ContractTls13HttpVerifiedSessionTrafficUpdateResult {
    contractTls13ApplyPeerTrafficUpdateToVerifiedSession(
        session,
        encodedKeyUpdate
    )
}

public func bridgeTls13ApplyPeerTrafficUpdateToVerifiedSessionRequest(
    request: BridgeTls13HttpVerifiedSessionPeerKeyUpdateRequest
): ContractTls13HttpVerifiedSessionTrafficUpdateResult {
    contractTls13ApplyPeerTrafficUpdateToVerifiedSessionRequest(
        ContractTls13HttpVerifiedSessionPeerKeyUpdateRequest(
            request.session,
            request.encodedKeyUpdate
        )
    )
}

public func bridgeTryBuildHttpClientHelloPskFromSessionCacheOutcome(
    cache: ContractTlsSessionCache,
    identity: ContractTlsSessionIdentity,
    nowUnixSeconds!: Int64 = 0,
    sessionId!: Array<Byte> = []
): ContractTls13PskClientHelloFromCacheOutcome {
    contractTryBuildHttpClientHelloPskFromSessionCacheOutcome(
        cache,
        identity,
        nowUnixSeconds: nowUnixSeconds,
        sessionId: sessionId
    )
}

public func bridgeTls13TryBuildHttpClientHelloPskFromSessionCache(
    cache: ContractTlsSessionCache,
    identity: ContractTlsSessionIdentity,
    nowUnixSeconds!: Int64 = 0,
    sessionId!: Array<Byte> = []
): ?ContractTls13PskClientHelloFromCacheResult {
    contractTls13TryBuildHttpClientHelloPskFromSessionCache(
        cache,
        identity,
        nowUnixSeconds: nowUnixSeconds,
        sessionId: sessionId
    )
}

public func bridgeTls13TryBuildHttpClientHelloPskFromSessionCacheRequest(
    request: BridgeTls13PskClientHelloFromSessionCacheRequest
): ?ContractTls13PskClientHelloFromCacheResult {
    contractTls13TryBuildHttpClientHelloPskFromSessionCacheRequest(
        ContractTls13PskClientHelloFromSessionCacheRequest(
            request.cache,
            request.identity,
            nowUnixSeconds: request.nowUnixSeconds,
            sessionId: request.sessionId
        )
    )
}

public func bridgeTls13TryBuildHttpClientHelloPskFromSessionCacheWithPolicy(
    cache: ContractTlsSessionCache,
    identity: ContractTlsSessionIdentity,
    policy!: ContractTls13SessionTicketPolicy = ContractTls13SessionTicketPolicy(),
    nowUnixSeconds!: Int64 = 0,
    sessionId!: Array<Byte> = []
): ?ContractTls13PskClientHelloFromCacheResult {
    contractTls13TryBuildHttpClientHelloPskFromSessionCacheWithPolicy(
        cache,
        identity,
        policy: policy,
        nowUnixSeconds: nowUnixSeconds,
        sessionId: sessionId
    )
}

public func bridgeTls13TryBuildHttpClientHelloPskFromSessionCacheWithPolicyRequest(
    request: BridgeTls13PskClientHelloFromSessionCacheWithPolicyRequest
): ?ContractTls13PskClientHelloFromCacheResult {
    contractTls13TryBuildHttpClientHelloPskFromSessionCacheWithPolicyRequest(
        ContractTls13PskClientHelloFromSessionCacheWithPolicyRequest(
            request.cache,
            request.identity,
            policy: request.policy,
            nowUnixSeconds: request.nowUnixSeconds,
            sessionId: request.sessionId
        )
    )
}

public func bridgeTls13BuildHttpClientHelloPskFromSessionTicket(
    ticket: ContractTlsSessionTicket,
    sessionId!: Array<Byte> = []
): Array<Byte> {
    contractTls13BuildHttpClientHelloPskFromSessionTicket(
        ticket,
        sessionId: sessionId
    )
}

public func bridgeTls13BuildHttpClientHelloPskFromSessionTicketRequest(
    request: BridgeTls13PskClientHelloFromSessionTicketRequest
): Array<Byte> {
    contractTls13BuildHttpClientHelloPskFromSessionTicket(
        request.ticket,
        sessionId: request.sessionId
    )
}

public func bridgeTls13BuildHttpClientHelloPskFromSessionTickets(
    tickets: Array<ContractTlsSessionTicket>,
    sessionId!: Array<Byte> = []
): Array<Byte> {
    contractTls13BuildHttpClientHelloPskFromSessionTickets(
        tickets,
        sessionId: sessionId
    )
}

public func bridgeTls13BuildHttpClientHelloPskFromSessionTicketsRequest(
    request: BridgeTls13PskClientHelloFromSessionTicketsRequest
): Array<Byte> {
    contractTls13BuildHttpClientHelloPskFromSessionTickets(
        request.tickets,
        sessionId: request.sessionId
    )
}

public func bridgeTls13BuildHttpServerHelloForPskFromSessionTicket(
    encodedClientHello: Array<Byte>,
    selectedIdentityIndex!: Int64 = 0,
    nowUnixSeconds!: Int64 = 0
): Array<Byte> {
    contractTls13BuildHttpServerHelloForPskFromSessionTicket(
        encodedClientHello,
        selectedIdentityIndex: selectedIdentityIndex,
        nowUnixSeconds: nowUnixSeconds
    )
}

public func bridgeTls13BuildHttpServerHelloForPskFromSessionTicketRequest(
    request: BridgeTls13PskServerHelloFromSessionTicketRequest
): Array<Byte> {
    contractTls13BuildHttpServerHelloForPskFromSessionTicket(
        request.encodedClientHello,
        selectedIdentityIndex: request.selectedIdentityIndex,
        nowUnixSeconds: request.nowUnixSeconds
    )
}

public func bridgeTls13BuildHttpServerHelloForPskBySessionTickets(
    encodedClientHello: Array<Byte>,
    nowUnixSeconds!: Int64 = 0
): Array<Byte> {
    contractTls13BuildHttpServerHelloForPskBySessionTickets(
        encodedClientHello,
        nowUnixSeconds: nowUnixSeconds
    )
}

public func bridgeTls13BuildHttpServerHelloForPskBySessionTicketsRequest(
    request: BridgeTls13PskServerHelloBySessionTicketsRequest
): Array<Byte> {
    contractTls13BuildHttpServerHelloForPskBySessionTickets(
        request.encodedClientHello,
        nowUnixSeconds: request.nowUnixSeconds
    )
}

public func bridgeTls13ExtractClientPskSessionTicket(
    encodedClientHello: Array<Byte>,
    selectedIdentityIndex!: Int64 = 0
): ContractTlsSessionTicket {
    contractTls13ExtractClientPskSessionTicket(
        encodedClientHello,
        selectedIdentityIndex: selectedIdentityIndex
    )
}

public func bridgeTls13ExtractClientPskSessionTicketRequest(
    request: BridgeTls13ExtractClientPskSessionTicketRequest
): ContractTlsSessionTicket {
    contractTls13ExtractClientPskSessionTicket(
        request.encodedClientHello,
        selectedIdentityIndex: request.selectedIdentityIndex
    )
}

public func bridgeTls13ExtractServerSelectedPskIdentity(
    encodedServerHello: Array<Byte>
): Int64 {
    contractTls13ExtractServerSelectedPskIdentity(encodedServerHello)
}

public func bridgeTls13ExtractServerSelectedPskIdentityRequest(
    request: BridgeTls13ExtractServerSelectedPskIdentityRequest
): Int64 {
    contractTls13ExtractServerSelectedPskIdentity(request.encodedServerHello)
}

public func bridgeTls13SelectPskIdentityFromSessionTickets(
    encodedClientHello: Array<Byte>,
    nowUnixSeconds!: Int64 = 0
): Int64 {
    contractTls13SelectPskIdentityFromSessionTickets(
        encodedClientHello,
        nowUnixSeconds: nowUnixSeconds
    )
}

public func bridgeTls13BuildHttpClientHelloPskFromSessionCache(
    cache: ContractTlsSessionCache,
    identity: ContractTlsSessionIdentity,
    nowUnixSeconds!: Int64 = 0,
    sessionId!: Array<Byte> = []
): ContractTls13PskClientHelloFromCacheResult {
    contractTls13BuildHttpClientHelloPskFromSessionCache(
        cache,
        identity,
        nowUnixSeconds: nowUnixSeconds,
        sessionId: sessionId
    )
}

public func bridgeTls13BuildHttpClientHelloPskFromSessionCacheRequest(
    request: BridgeTls13PskClientHelloFromSessionCacheRequest
): ContractTls13PskClientHelloFromCacheResult {
    contractTls13BuildHttpClientHelloPskFromSessionCacheRequest(
        ContractTls13PskClientHelloFromSessionCacheRequest(
            request.cache,
            request.identity,
            nowUnixSeconds: request.nowUnixSeconds,
            sessionId: request.sessionId
        )
    )
}

public func bridgeTls13BuildHttpClientHelloPskFromSessionCacheWithPolicy(
    cache: ContractTlsSessionCache,
    identity: ContractTlsSessionIdentity,
    policy!: ContractTls13SessionTicketPolicy = ContractTls13SessionTicketPolicy(),
    nowUnixSeconds!: Int64 = 0,
    sessionId!: Array<Byte> = []
): ContractTls13PskClientHelloFromCacheResult {
    contractTls13BuildHttpClientHelloPskFromSessionCacheWithPolicy(
        cache,
        identity,
        policy: policy,
        nowUnixSeconds: nowUnixSeconds,
        sessionId: sessionId
    )
}

public func bridgeTls13BuildHttpClientHelloPskFromSessionCacheWithPolicyRequest(
    request: BridgeTls13PskClientHelloFromSessionCacheWithPolicyRequest
): ContractTls13PskClientHelloFromCacheResult {
    contractTls13BuildHttpClientHelloPskFromSessionCacheWithPolicyRequest(
        ContractTls13PskClientHelloFromSessionCacheWithPolicyRequest(
            request.cache,
            request.identity,
            policy: request.policy,
            nowUnixSeconds: request.nowUnixSeconds,
            sessionId: request.sessionId
        )
    )
}

public func bridgeTryBuildHttpClientHelloPskFromSessionCacheRequest(
    request: BridgeTls13PskClientHelloFromSessionCacheRequest
): ?ContractTls13PskClientHelloFromCacheResult {
    contractTls13TryBuildHttpClientHelloPskFromSessionCacheRequest(
        ContractTls13PskClientHelloFromSessionCacheRequest(
            request.cache,
            request.identity,
            nowUnixSeconds: request.nowUnixSeconds,
            sessionId: request.sessionId
        )
    )
}

public func bridgeTryBuildHttpClientHelloPskFromSessionCacheRequestOutcome(
    request: BridgeTls13PskClientHelloFromSessionCacheRequest
): ContractTls13PskClientHelloFromCacheOutcome {
    contractTryBuildHttpClientHelloPskFromSessionCacheRequestOutcome(
        ContractTls13PskClientHelloFromSessionCacheRequest(
            request.cache,
            request.identity,
            nowUnixSeconds: request.nowUnixSeconds,
            sessionId: request.sessionId
        )
    )
}

public func bridgeTryBuildHttpClientHelloPskFromSessionCacheWithPolicyOutcome(
    cache: ContractTlsSessionCache,
    identity: ContractTlsSessionIdentity,
    policy!: ContractTls13SessionTicketPolicy = ContractTls13SessionTicketPolicy(),
    nowUnixSeconds!: Int64 = 0,
    sessionId!: Array<Byte> = []
): ContractTls13PskClientHelloFromCacheOutcome {
    contractTryBuildHttpClientHelloPskFromSessionCacheWithPolicyOutcome(
        cache,
        identity,
        policy: policy,
        nowUnixSeconds: nowUnixSeconds,
        sessionId: sessionId
    )
}

public func bridgeTryBuildHttpClientHelloPskFromSessionCacheWithPolicyRequest(
    request: BridgeTls13PskClientHelloFromSessionCacheWithPolicyRequest
): ?ContractTls13PskClientHelloFromCacheResult {
    contractTls13TryBuildHttpClientHelloPskFromSessionCacheWithPolicyRequest(
        ContractTls13PskClientHelloFromSessionCacheWithPolicyRequest(
            request.cache,
            request.identity,
            policy: request.policy,
            nowUnixSeconds: request.nowUnixSeconds,
            sessionId: request.sessionId
        )
    )
}

public func bridgeTryBuildHttpClientHelloPskFromSessionCacheWithPolicyRequestOutcome(
    request: BridgeTls13PskClientHelloFromSessionCacheWithPolicyRequest
): ContractTls13PskClientHelloFromCacheOutcome {
    contractTryBuildHttpClientHelloPskFromSessionCacheWithPolicyRequestOutcome(
        ContractTls13PskClientHelloFromSessionCacheWithPolicyRequest(
            request.cache,
            request.identity,
            policy: request.policy,
            nowUnixSeconds: request.nowUnixSeconds,
            sessionId: request.sessionId
        )
    )
}

public func bridgeTls13EvaluateSessionTicketLifecycleRequest(
    request: BridgeTls13SessionTicketLifecycleRequest
): ContractTls13SessionTicketLifecycleResult {
    contractTls13EvaluateSessionTicketLifecycleRequest(
        ContractTls13SessionTicketLifecycleRequest(
            request.ticket,
            policy: request.policy,
            nowUnixSeconds: request.nowUnixSeconds
        )
    )
}

public func bridgeTls13EvaluateSessionTicketLifecycle(
    ticket: ContractTlsSessionTicket,
    policy!: ContractTls13SessionTicketPolicy = ContractTls13SessionTicketPolicy(),
    nowUnixSeconds!: Int64 = 0
): ContractTls13SessionTicketLifecycleResult {
    contractTls13EvaluateSessionTicketLifecycle(
        ticket,
        policy: policy,
        nowUnixSeconds: nowUnixSeconds
    )
}

public func bridgeTls13RequireUsableSessionTicketRequest(
    request: BridgeTls13SessionTicketLifecycleRequest
): ContractTls13SessionTicketLifecycleResult {
    contractTls13RequireUsableSessionTicketRequest(
        ContractTls13SessionTicketLifecycleRequest(
            request.ticket,
            policy: request.policy,
            nowUnixSeconds: request.nowUnixSeconds
        )
    )
}

public func bridgeTls13RequireUsableSessionTicket(
    ticket: ContractTlsSessionTicket,
    policy!: ContractTls13SessionTicketPolicy = ContractTls13SessionTicketPolicy(),
    nowUnixSeconds!: Int64 = 0
): ContractTls13SessionTicketLifecycleResult {
    contractTls13RequireUsableSessionTicket(
        ticket,
        policy: policy,
        nowUnixSeconds: nowUnixSeconds
    )
}

public func bridgeTls13BuildNewSessionTicketFromSessionTicket(
    ticket: ContractTlsSessionTicket,
    ticketAgeAdd!: Int64 = 0
): Array<Byte> {
    contractTls13BuildNewSessionTicketFromSessionTicket(
        ticket,
        ticketAgeAdd: ticketAgeAdd
    )
}

public func bridgeTls13BuildNewSessionTicketFromSessionTicketRequest(
    request: BridgeTls13NewSessionTicketRequest
): Array<Byte> {
    contractTls13BuildNewSessionTicketFromSessionTicketRequest(
        ContractTls13NewSessionTicketRequest(
            request.ticket,
            ticketAgeAdd: request.ticketAgeAdd
        )
    )
}

public func bridgeTls13DecodeSessionTicketFromNewSessionTicket(
    encodedNewSessionTicket: Array<Byte>
): ContractTlsSessionTicket {
    contractTls13DecodeSessionTicketFromNewSessionTicket(encodedNewSessionTicket)
}

public func bridgeTls13StoreNewSessionTicketToCache(
    cache: ContractTlsSessionCache,
    encodedNewSessionTicket: Array<Byte>
): ContractTlsSessionTicket {
    contractTls13StoreNewSessionTicketToCache(cache, encodedNewSessionTicket)
}

public func bridgeTls13StoreNewSessionTicketToCacheRequest(
    request: BridgeTls13StoreNewSessionTicketRequest
): ContractTlsSessionTicket {
    contractTls13StoreNewSessionTicketToCacheRequest(
        ContractTls13StoreNewSessionTicketRequest(
            request.cache,
            request.encodedNewSessionTicket
        )
    )
}

public func bridgeTls13PreparePskEarlyDataFromSessionTicketRequest(
    request: BridgeTls13PskEarlyDataFromSessionTicketRequest
): ContractTls13PskEarlyDataPlan {
    contractTls13PreparePskEarlyDataFromSessionTicketRequest(
        ContractTls13PskEarlyDataFromSessionTicketRequest(
            request.ticket,
            sessionId: request.sessionId,
            keyLen: request.keyLen,
            ivLen: request.ivLen
        )
    )
}

public func bridgeTls13PreparePskEarlyDataFromSessionTicket(
    ticket: ContractTlsSessionTicket,
    sessionId!: Array<Byte> = [],
    keyLen!: Int64 = 16,
    ivLen!: Int64 = 12
): ContractTls13PskEarlyDataPlan {
    contractTls13PreparePskEarlyDataFromSessionTicket(
        ticket,
        sessionId: sessionId,
        keyLen: keyLen,
        ivLen: ivLen
    )
}

public func bridgeTls13PreparePskEarlyDataFromSessionCacheRequest(
    request: BridgeTls13PskEarlyDataFromSessionCacheRequest
): ContractTls13PskEarlyDataPlan {
    contractTls13PreparePskEarlyDataFromSessionCacheRequest(
        ContractTls13PskEarlyDataFromSessionCacheRequest(
            request.cache,
            request.identity,
            nowUnixSeconds: request.nowUnixSeconds,
            sessionId: request.sessionId,
            keyLen: request.keyLen,
            ivLen: request.ivLen
        )
    )
}

public func bridgeTls13PreparePskEarlyDataFromSessionCache(
    cache: ContractTlsSessionCache,
    identity: ContractTlsSessionIdentity,
    nowUnixSeconds!: Int64 = 0,
    sessionId!: Array<Byte> = [],
    keyLen!: Int64 = 16,
    ivLen!: Int64 = 12
): ContractTls13PskEarlyDataPlan {
    contractTls13PreparePskEarlyDataFromSessionCache(
        cache,
        identity,
        nowUnixSeconds: nowUnixSeconds,
        sessionId: sessionId,
        keyLen: keyLen,
        ivLen: ivLen
    )
}

public func bridgeTls13AcceptPskEarlyDataFromClientHelloRequest(
    request: BridgeTls13PskEarlyDataAcceptRequest
): ContractTls13PskEarlyDataPlan {
    contractTls13AcceptPskEarlyDataFromClientHelloRequest(
        ContractTls13PskEarlyDataAcceptRequest(
            request.encodedClientHello,
            nowUnixSeconds: request.nowUnixSeconds,
            selectedIdentityIndex: request.selectedIdentityIndex,
            keyLen: request.keyLen,
            ivLen: request.ivLen
        )
    )
}

public func bridgeTls13AcceptPskEarlyDataFromClientHello(
    encodedClientHello: Array<Byte>,
    nowUnixSeconds!: Int64 = 0,
    selectedIdentityIndex!: Int64 = -1,
    keyLen!: Int64 = 16,
    ivLen!: Int64 = 12
): ContractTls13PskEarlyDataPlan {
    contractTls13AcceptPskEarlyDataFromClientHello(
        encodedClientHello,
        nowUnixSeconds: nowUnixSeconds,
        selectedIdentityIndex: selectedIdentityIndex,
        keyLen: keyLen,
        ivLen: ivLen
    )
}

public func bridgeTls13BuildPskEarlyDataReplayKey(
    plan: ContractTls13PskEarlyDataPlan
): String {
    contractTls13BuildPskEarlyDataReplayKey(plan)
}

public func bridgeTls13AcceptPskEarlyDataFromClientHelloWithReplayCacheRequest(
    request: BridgeTls13PskEarlyDataAcceptWithReplayCacheRequest
): ContractTls13PskEarlyDataPlan {
    contractTls13AcceptPskEarlyDataFromClientHelloWithReplayCacheRequest(
        ContractTls13PskEarlyDataAcceptWithReplayCacheRequest(
            request.encodedClientHello,
            request.replayCache,
            nowUnixSeconds: request.nowUnixSeconds,
            selectedIdentityIndex: request.selectedIdentityIndex,
            keyLen: request.keyLen,
            ivLen: request.ivLen,
            replayTtlSeconds: request.replayTtlSeconds
        )
    )
}

public func bridgeTls13AcceptPskEarlyDataFromClientHelloWithReplayCache(
    encodedClientHello: Array<Byte>,
    replayCache: ContractTls13EarlyDataReplayCache,
    nowUnixSeconds!: Int64 = 0,
    selectedIdentityIndex!: Int64 = -1,
    keyLen!: Int64 = 16,
    ivLen!: Int64 = 12,
    replayTtlSeconds!: Int64 = 0
): ContractTls13PskEarlyDataPlan {
    contractTls13AcceptPskEarlyDataFromClientHelloWithReplayCache(
        encodedClientHello,
        replayCache,
        nowUnixSeconds: nowUnixSeconds,
        selectedIdentityIndex: selectedIdentityIndex,
        keyLen: keyLen,
        ivLen: ivLen,
        replayTtlSeconds: replayTtlSeconds
    )
}

public func bridgeTls13AcceptPskEarlyDataForHttpRequest(
    request: BridgeTls13PskEarlyDataHttpAcceptRequest
): ContractTls13PskEarlyDataPlan {
    contractTls13AcceptPskEarlyDataForHttpRequest(
        ContractTls13PskEarlyDataHttpAcceptRequest(
            request.encodedClientHello,
            expectedServerName: request.expectedServerName,
            expectedAlpnProtocol: request.expectedAlpnProtocol,
            nowUnixSeconds: request.nowUnixSeconds,
            selectedIdentityIndex: request.selectedIdentityIndex,
            keyLen: request.keyLen,
            ivLen: request.ivLen
        )
    )
}

public func bridgeTls13AcceptPskEarlyDataForHttp(
    encodedClientHello: Array<Byte>,
    expectedServerName!: String = "",
    expectedAlpnProtocol!: String = "",
    nowUnixSeconds!: Int64 = 0,
    selectedIdentityIndex!: Int64 = -1,
    keyLen!: Int64 = 16,
    ivLen!: Int64 = 12
): ContractTls13PskEarlyDataPlan {
    contractTls13AcceptPskEarlyDataForHttp(
        encodedClientHello,
        expectedServerName: expectedServerName,
        expectedAlpnProtocol: expectedAlpnProtocol,
        nowUnixSeconds: nowUnixSeconds,
        selectedIdentityIndex: selectedIdentityIndex,
        keyLen: keyLen,
        ivLen: ivLen
    )
}

public func bridgeTls13AcceptPskEarlyDataForHttpWithReplayCacheRequest(
    request: BridgeTls13PskEarlyDataHttpAcceptWithReplayCacheRequest
): ContractTls13PskEarlyDataPlan {
    contractTls13AcceptPskEarlyDataForHttpWithReplayCacheRequest(
        ContractTls13PskEarlyDataHttpAcceptWithReplayCacheRequest(
            request.encodedClientHello,
            request.replayCache,
            expectedServerName: request.expectedServerName,
            expectedAlpnProtocol: request.expectedAlpnProtocol,
            nowUnixSeconds: request.nowUnixSeconds,
            selectedIdentityIndex: request.selectedIdentityIndex,
            keyLen: request.keyLen,
            ivLen: request.ivLen,
            replayTtlSeconds: request.replayTtlSeconds
        )
    )
}

public func bridgeTls13AcceptPskEarlyDataForHttpWithReplayCache(
    encodedClientHello: Array<Byte>,
    replayCache: ContractTls13EarlyDataReplayCache,
    expectedServerName!: String = "",
    expectedAlpnProtocol!: String = "",
    nowUnixSeconds!: Int64 = 0,
    selectedIdentityIndex!: Int64 = -1,
    keyLen!: Int64 = 16,
    ivLen!: Int64 = 12,
    replayTtlSeconds!: Int64 = 0
): ContractTls13PskEarlyDataPlan {
    contractTls13AcceptPskEarlyDataForHttpWithReplayCache(
        encodedClientHello,
        replayCache,
        expectedServerName: expectedServerName,
        expectedAlpnProtocol: expectedAlpnProtocol,
        nowUnixSeconds: nowUnixSeconds,
        selectedIdentityIndex: selectedIdentityIndex,
        keyLen: keyLen,
        ivLen: ivLen,
        replayTtlSeconds: replayTtlSeconds
    )
}

public func bridgeSshCompleteServerInitialHandshakeX25519RsaPkcs8Request(
    request: BridgeSshServerInitialHandshakeX25519RsaPkcs8Request
): ContractSshServerInitialHandshakeResult {
    let hostPrivateKey = x509ParseRsaPrivateKeyPkcs8Pem(request.hostPrivateKeyPkcs8Pem)
    bridgeSshCompleteServerInitialHandshakeX25519Rsa(
        bridgeToSshTranscript(request.transcript),
        request.serverPrivateKey,
        request.encodedClientInit,
        hostPrivateKey,
        bridgeToSshNegotiatedAlgorithms(request.negotiated),
        request.encodedClientNewKeys,
        request.encodedServerNewKeys,
        signatureAlgorithm: request.signatureAlgorithm,
        serverPublicKey: request.serverPublicKey
    )
}

public func bridgeTrySshCompleteServerInitialHandshakeX25519RsaPkcs8Request(
    request: BridgeSshServerInitialHandshakeX25519RsaPkcs8Request
): ContractSshServerInitialHandshakeOutcome {
    try {
        let hostPrivateKey = x509ParseRsaPrivateKeyPkcs8Pem(request.hostPrivateKeyPkcs8Pem)
        bridgeTrySshCompleteServerInitialHandshakeX25519Rsa(
            bridgeToSshTranscript(request.transcript),
            request.serverPrivateKey,
            request.encodedClientInit,
            hostPrivateKey,
            bridgeToSshNegotiatedAlgorithms(request.negotiated),
            request.encodedClientNewKeys,
            request.encodedServerNewKeys,
            signatureAlgorithm: request.signatureAlgorithm,
            serverPublicKey: request.serverPublicKey
        )
    } catch (e: ContractException) {
        ContractSshServerInitialHandshakeOutcome(
            false,
            e.message,
            code: Some(e.code),
            igniteCode: Some(contractMapToIgniteCryptoErrorCode(e.code))
        )
    } catch (e: CryptoException) {
        let code = contractMapCryptoExceptionToErrorCode(e)
        ContractSshServerInitialHandshakeOutcome(
            false,
            "SSH RSA server initial handshake request failed: ${e.message}",
            code: Some(code),
            igniteCode: Some(contractMapToIgniteCryptoErrorCode(code))
        )
    }
}

public func bridgeSshCompleteServerInitialHandshakeX25519EcdsaPkcs8Request(
    request: BridgeSshServerInitialHandshakeX25519EcdsaPkcs8Request
): ContractSshServerInitialHandshakeResult {
    let hostPrivateKey = x509ParseEcPrivateKeyPkcs8Pem(request.hostPrivateKeyPkcs8Pem)
    bridgeSshCompleteServerInitialHandshakeX25519Ecdsa(
        bridgeToSshTranscript(request.transcript),
        request.serverPrivateKey,
        request.encodedClientInit,
        hostPrivateKey,
        bridgeToSshNegotiatedAlgorithms(request.negotiated),
        request.encodedClientNewKeys,
        request.encodedServerNewKeys,
        serverPublicKey: request.serverPublicKey
    )
}

public func bridgeTrySshCompleteServerInitialHandshakeX25519EcdsaPkcs8Request(
    request: BridgeSshServerInitialHandshakeX25519EcdsaPkcs8Request
): ContractSshServerInitialHandshakeOutcome {
    try {
        let hostPrivateKey = x509ParseEcPrivateKeyPkcs8Pem(request.hostPrivateKeyPkcs8Pem)
        bridgeTrySshCompleteServerInitialHandshakeX25519Ecdsa(
            bridgeToSshTranscript(request.transcript),
            request.serverPrivateKey,
            request.encodedClientInit,
            hostPrivateKey,
            bridgeToSshNegotiatedAlgorithms(request.negotiated),
            request.encodedClientNewKeys,
            request.encodedServerNewKeys,
            serverPublicKey: request.serverPublicKey
        )
    } catch (e: ContractException) {
        ContractSshServerInitialHandshakeOutcome(
            false,
            e.message,
            code: Some(e.code),
            igniteCode: Some(contractMapToIgniteCryptoErrorCode(e.code))
        )
    } catch (e: CryptoException) {
        let code = contractMapCryptoExceptionToErrorCode(e)
        ContractSshServerInitialHandshakeOutcome(
            false,
            "SSH ECDSA server initial handshake request failed: ${e.message}",
            code: Some(code),
            igniteCode: Some(contractMapToIgniteCryptoErrorCode(code))
        )
    }
}

public func bridgeSshCompleteServerInitialHandshakeX25519Ed25519SeedRequest(
    request: BridgeSshServerInitialHandshakeX25519Ed25519SeedRequest
): ContractSshServerInitialHandshakeResult {
    bridgeSshCompleteServerInitialHandshakeX25519Ed25519(
        bridgeToSshTranscript(request.transcript),
        request.serverPrivateKey,
        request.encodedClientInit,
        request.hostPrivateKeySeed,
        bridgeToSshNegotiatedAlgorithms(request.negotiated),
        request.encodedClientNewKeys,
        request.encodedServerNewKeys,
        serverPublicKey: request.serverPublicKey
    )
}

public func bridgeTrySshCompleteServerInitialHandshakeX25519Ed25519SeedRequest(
    request: BridgeSshServerInitialHandshakeX25519Ed25519SeedRequest
): ContractSshServerInitialHandshakeOutcome {
    bridgeTrySshCompleteServerInitialHandshakeX25519Ed25519(
        bridgeToSshTranscript(request.transcript),
        request.serverPrivateKey,
        request.encodedClientInit,
        request.hostPrivateKeySeed,
        bridgeToSshNegotiatedAlgorithms(request.negotiated),
        request.encodedClientNewKeys,
        request.encodedServerNewKeys,
        serverPublicKey: request.serverPublicKey
    )
}

public func bridgeSshComputeHostKeySha256(serverHostKey: Array<Byte>): Array<Byte> {
    contractSshComputeHostKeySha256(serverHostKey)
}

public func bridgeSshEncodeRsaHostPublicKey(publicKey: RsaPublicKey): Array<Byte> {
    contractSshEncodeRsaHostPublicKey(publicKey)
}

public func bridgeSshEncodeRsaHostPublicKeyPkcs8Pem(privateKeyPkcs8Pem: String): Array<Byte> {
    let privateKey = x509ParseRsaPrivateKeyPkcs8Pem(privateKeyPkcs8Pem)
    bridgeSshEncodeRsaHostPublicKey(privateKey.publicKey)
}

public func bridgeSshSignExchangeHashRsa(
    privateKey: RsaPrivateKey,
    exchangeHash: Array<Byte>,
    signatureAlgorithm!: String = "rsa-sha2-256"
): Array<Byte> {
    contractSshSignExchangeHashRsa(
        privateKey,
        exchangeHash,
        signatureAlgorithm: signatureAlgorithm
    )
}

public func bridgeSshSignExchangeHashRsaPkcs8Pem(
    privateKeyPkcs8Pem: String,
    exchangeHash: Array<Byte>,
    signatureAlgorithm!: String = "rsa-sha2-256"
): Array<Byte> {
    let privateKey = x509ParseRsaPrivateKeyPkcs8Pem(privateKeyPkcs8Pem)
    bridgeSshSignExchangeHashRsa(
        privateKey,
        exchangeHash,
        signatureAlgorithm: signatureAlgorithm
    )
}

public func bridgeSshEncodeEcdsaHostPublicKey(publicKey: EcPublicKey): Array<Byte> {
    contractSshEncodeEcdsaHostPublicKey(publicKey)
}

public func bridgeSshEncodeEcdsaHostPublicKeyPkcs8Pem(privateKeyPkcs8Pem: String): Array<Byte> {
    let privateKey = x509ParseEcPrivateKeyPkcs8Pem(privateKeyPkcs8Pem)
    bridgeSshEncodeEcdsaHostPublicKey(ecPublicFromPrivateKey(privateKey))
}

public func bridgeSshSignExchangeHashEcdsa(privateKey: EcPrivateKey, exchangeHash: Array<Byte>): Array<Byte> {
    contractSshSignExchangeHashEcdsa(privateKey, exchangeHash)
}

public func bridgeSshSignExchangeHashEcdsaPkcs8Pem(
    privateKeyPkcs8Pem: String,
    exchangeHash: Array<Byte>
): Array<Byte> {
    let privateKey = x509ParseEcPrivateKeyPkcs8Pem(privateKeyPkcs8Pem)
    bridgeSshSignExchangeHashEcdsa(privateKey, exchangeHash)
}

public func bridgeSshPrepareHostSigningRsa(
    privateKey: RsaPrivateKey,
    exchangeHash: Array<Byte>,
    signatureAlgorithm!: String = "rsa-sha2-256"
): ContractSshHostSigningResult {
    contractPrepareSshHostSigningRsa(
        privateKey,
        exchangeHash,
        signatureAlgorithm: signatureAlgorithm
    )
}

public func bridgeTrySshPrepareHostSigningRsa(
    privateKey: RsaPrivateKey,
    exchangeHash: Array<Byte>,
    signatureAlgorithm!: String = "rsa-sha2-256"
): ContractSshHostSigningOutcome {
    contractTryPrepareSshHostSigningRsa(
        privateKey,
        exchangeHash,
        signatureAlgorithm: signatureAlgorithm
    )
}

public func bridgeSshPrepareHostSigningRsaPkcs8Pem(
    privateKeyPkcs8Pem: String,
    exchangeHash: Array<Byte>,
    signatureAlgorithm!: String = "rsa-sha2-256"
): ContractSshHostSigningResult {
    bridgeSshPrepareHostSigningRsaPkcs8Request(
        BridgeSshHostSigningRsaPkcs8Request(
            privateKeyPkcs8Pem,
            exchangeHash,
            signatureAlgorithm: signatureAlgorithm
        )
    )
}

public func bridgeSshPrepareHostSigningRsaPkcs8Request(
    request: BridgeSshHostSigningRsaPkcs8Request
): ContractSshHostSigningResult {
    contractPrepareSshHostSigningRsaPkcs8Request(
        ContractSshHostSigningRsaPkcs8Request(
            request.hostPrivateKeyPkcs8Pem,
            request.exchangeHash,
            signatureAlgorithm: request.signatureAlgorithm
        )
    )
}

public func bridgeTrySshPrepareHostSigningRsaPkcs8Pem(
    privateKeyPkcs8Pem: String,
    exchangeHash: Array<Byte>,
    signatureAlgorithm!: String = "rsa-sha2-256"
): ContractSshHostSigningOutcome {
    bridgeTrySshPrepareHostSigningRsaPkcs8Request(
        BridgeSshHostSigningRsaPkcs8Request(
            privateKeyPkcs8Pem,
            exchangeHash,
            signatureAlgorithm: signatureAlgorithm
        )
    )
}

public func bridgeTrySshPrepareHostSigningRsaPkcs8Request(
    request: BridgeSshHostSigningRsaPkcs8Request
): ContractSshHostSigningOutcome {
    contractTryPrepareSshHostSigningRsaPkcs8Request(
        ContractSshHostSigningRsaPkcs8Request(
            request.hostPrivateKeyPkcs8Pem,
            request.exchangeHash,
            signatureAlgorithm: request.signatureAlgorithm
        )
    )
}

public func bridgeSshPrepareHostSigningEcdsa(
    privateKey: EcPrivateKey,
    exchangeHash: Array<Byte>
): ContractSshHostSigningResult {
    contractPrepareSshHostSigningEcdsa(privateKey, exchangeHash)
}

public func bridgeTrySshPrepareHostSigningEcdsa(
    privateKey: EcPrivateKey,
    exchangeHash: Array<Byte>
): ContractSshHostSigningOutcome {
    contractTryPrepareSshHostSigningEcdsa(privateKey, exchangeHash)
}

public func bridgeSshPrepareHostSigningEcdsaPkcs8Pem(
    privateKeyPkcs8Pem: String,
    exchangeHash: Array<Byte>
): ContractSshHostSigningResult {
    bridgeSshPrepareHostSigningEcdsaPkcs8Request(
        BridgeSshHostSigningEcdsaPkcs8Request(privateKeyPkcs8Pem, exchangeHash)
    )
}

public func bridgeSshPrepareHostSigningEcdsaPkcs8Request(
    request: BridgeSshHostSigningEcdsaPkcs8Request
): ContractSshHostSigningResult {
    contractPrepareSshHostSigningEcdsaPkcs8Request(
        ContractSshHostSigningEcdsaPkcs8Request(
            request.hostPrivateKeyPkcs8Pem,
            request.exchangeHash
        )
    )
}

public func bridgeTrySshPrepareHostSigningEcdsaPkcs8Pem(
    privateKeyPkcs8Pem: String,
    exchangeHash: Array<Byte>
): ContractSshHostSigningOutcome {
    bridgeTrySshPrepareHostSigningEcdsaPkcs8Request(
        BridgeSshHostSigningEcdsaPkcs8Request(privateKeyPkcs8Pem, exchangeHash)
    )
}

public func bridgeTrySshPrepareHostSigningEcdsaPkcs8Request(
    request: BridgeSshHostSigningEcdsaPkcs8Request
): ContractSshHostSigningOutcome {
    contractTryPrepareSshHostSigningEcdsaPkcs8Request(
        ContractSshHostSigningEcdsaPkcs8Request(
            request.hostPrivateKeyPkcs8Pem,
            request.exchangeHash
        )
    )
}

public func bridgeSshPrepareHostSigningEd25519(
    privateKeySeed: Array<Byte>,
    exchangeHash: Array<Byte>
): ContractSshHostSigningResult {
    contractPrepareSshHostSigningEd25519(privateKeySeed, exchangeHash)
}

public func bridgeTrySshPrepareHostSigningEd25519(
    privateKeySeed: Array<Byte>,
    exchangeHash: Array<Byte>
): ContractSshHostSigningOutcome {
    contractTryPrepareSshHostSigningEd25519(privateKeySeed, exchangeHash)
}

public func bridgeSshPrepareHostSigningEd25519SeedRequest(
    request: BridgeSshHostSigningEd25519SeedRequest
): ContractSshHostSigningResult {
    contractPrepareSshHostSigningEd25519SeedRequest(
        ContractSshHostSigningEd25519SeedRequest(
            request.hostPrivateKeySeed,
            request.exchangeHash
        )
    )
}

public func bridgeTrySshPrepareHostSigningEd25519SeedRequest(
    request: BridgeSshHostSigningEd25519SeedRequest
): ContractSshHostSigningOutcome {
    contractTryPrepareSshHostSigningEd25519SeedRequest(
        ContractSshHostSigningEd25519SeedRequest(
            request.hostPrivateKeySeed,
            request.exchangeHash
        )
    )
}

public func bridgeSshBuildEd25519HostKeyBlobFromSeed(privateKeySeed: Array<Byte>): Array<Byte> {
    contractSshBuildEd25519HostKeyBlobFromSeed(privateKeySeed)
}

public func bridgeSshSignExchangeHashEd25519(privateKeySeed: Array<Byte>, exchangeHash: Array<Byte>): Array<Byte> {
    contractSshSignExchangeHashEd25519(privateKeySeed, exchangeHash)
}

public func bridgeSshVerifyHostIdentityRequired(
    exchangeHash: Array<Byte>,
    serverHostKey: Array<Byte>,
    hostSignature: Array<Byte>,
    policy!: ContractSshHostVerificationPolicy = ContractSshHostVerificationPolicy()
): ContractSshHostVerificationResult {
    contractSshVerifyHostIdentityRequired(
        exchangeHash,
        serverHostKey,
        hostSignature,
        policy: policy
    )
}

public func bridgeTrySshVerifyHostIdentityRequired(
    exchangeHash: Array<Byte>,
    serverHostKey: Array<Byte>,
    hostSignature: Array<Byte>,
    policy!: ContractSshHostVerificationPolicy = ContractSshHostVerificationPolicy()
): ContractSshHostVerificationOutcome {
    contractTrySshVerifyHostIdentityRequired(
        exchangeHash,
        serverHostKey,
        hostSignature,
        policy: policy
    )
}

public func bridgeSshCompleteServerInitialHandshakeX25519Rsa(
    transcript: SshKexExchangeTranscript,
    serverPrivateKey: Array<Byte>,
    encodedClientInit: Array<Byte>,
    hostPrivateKey: RsaPrivateKey,
    negotiated: SshNegotiatedAlgorithms,
    encodedClientNewKeys: Array<Byte>,
    encodedServerNewKeys: Array<Byte>,
    signatureAlgorithm!: String = "rsa-sha2-256",
    serverPublicKey!: Array<Byte> = []
): ContractSshServerInitialHandshakeResult {
    contractSshCompleteServerInitialHandshakeX25519Rsa(
        transcript,
        serverPrivateKey,
        encodedClientInit,
        hostPrivateKey,
        negotiated,
        encodedClientNewKeys,
        encodedServerNewKeys,
        signatureAlgorithm: signatureAlgorithm,
        serverPublicKey: serverPublicKey
    )
}

public func bridgeTrySshCompleteServerInitialHandshakeX25519Rsa(
    transcript: SshKexExchangeTranscript,
    serverPrivateKey: Array<Byte>,
    encodedClientInit: Array<Byte>,
    hostPrivateKey: RsaPrivateKey,
    negotiated: SshNegotiatedAlgorithms,
    encodedClientNewKeys: Array<Byte>,
    encodedServerNewKeys: Array<Byte>,
    signatureAlgorithm!: String = "rsa-sha2-256",
    serverPublicKey!: Array<Byte> = []
): ContractSshServerInitialHandshakeOutcome {
    contractTrySshCompleteServerInitialHandshakeX25519Rsa(
        transcript,
        serverPrivateKey,
        encodedClientInit,
        hostPrivateKey,
        negotiated,
        encodedClientNewKeys,
        encodedServerNewKeys,
        signatureAlgorithm: signatureAlgorithm,
        serverPublicKey: serverPublicKey
    )
}

public func bridgeSshCompleteServerInitialHandshakeX25519Ecdsa(
    transcript: SshKexExchangeTranscript,
    serverPrivateKey: Array<Byte>,
    encodedClientInit: Array<Byte>,
    hostPrivateKey: EcPrivateKey,
    negotiated: SshNegotiatedAlgorithms,
    encodedClientNewKeys: Array<Byte>,
    encodedServerNewKeys: Array<Byte>,
    serverPublicKey!: Array<Byte> = []
): ContractSshServerInitialHandshakeResult {
    contractSshCompleteServerInitialHandshakeX25519Ecdsa(
        transcript,
        serverPrivateKey,
        encodedClientInit,
        hostPrivateKey,
        negotiated,
        encodedClientNewKeys,
        encodedServerNewKeys,
        serverPublicKey: serverPublicKey
    )
}

public func bridgeTrySshCompleteServerInitialHandshakeX25519Ecdsa(
    transcript: SshKexExchangeTranscript,
    serverPrivateKey: Array<Byte>,
    encodedClientInit: Array<Byte>,
    hostPrivateKey: EcPrivateKey,
    negotiated: SshNegotiatedAlgorithms,
    encodedClientNewKeys: Array<Byte>,
    encodedServerNewKeys: Array<Byte>,
    serverPublicKey!: Array<Byte> = []
): ContractSshServerInitialHandshakeOutcome {
    contractTrySshCompleteServerInitialHandshakeX25519Ecdsa(
        transcript,
        serverPrivateKey,
        encodedClientInit,
        hostPrivateKey,
        negotiated,
        encodedClientNewKeys,
        encodedServerNewKeys,
        serverPublicKey: serverPublicKey
    )
}

public func bridgeSshCompleteServerInitialHandshakeX25519Ed25519(
    transcript: SshKexExchangeTranscript,
    serverPrivateKey: Array<Byte>,
    encodedClientInit: Array<Byte>,
    hostPrivateKeySeed: Array<Byte>,
    negotiated: SshNegotiatedAlgorithms,
    encodedClientNewKeys: Array<Byte>,
    encodedServerNewKeys: Array<Byte>,
    serverPublicKey!: Array<Byte> = []
): ContractSshServerInitialHandshakeResult {
    contractSshCompleteServerInitialHandshakeX25519Ed25519(
        transcript,
        serverPrivateKey,
        encodedClientInit,
        hostPrivateKeySeed,
        negotiated,
        encodedClientNewKeys,
        encodedServerNewKeys,
        serverPublicKey: serverPublicKey
    )
}

public func bridgeTrySshCompleteServerInitialHandshakeX25519Ed25519(
    transcript: SshKexExchangeTranscript,
    serverPrivateKey: Array<Byte>,
    encodedClientInit: Array<Byte>,
    hostPrivateKeySeed: Array<Byte>,
    negotiated: SshNegotiatedAlgorithms,
    encodedClientNewKeys: Array<Byte>,
    encodedServerNewKeys: Array<Byte>,
    serverPublicKey!: Array<Byte> = []
): ContractSshServerInitialHandshakeOutcome {
    contractTrySshCompleteServerInitialHandshakeX25519Ed25519(
        transcript,
        serverPrivateKey,
        encodedClientInit,
        hostPrivateKeySeed,
        negotiated,
        encodedClientNewKeys,
        encodedServerNewKeys,
        serverPublicKey: serverPublicKey
    )
}

public func bridgeSshCompleteClientInitialHandshakeX25519(
    transcript: SshKexExchangeTranscript,
    clientPrivateKey: Array<Byte>,
    encodedClientInit: Array<Byte>,
    encodedServerReply: Array<Byte>,
    negotiated: SshNegotiatedAlgorithms,
    encodedClientNewKeys: Array<Byte>,
    encodedServerNewKeys: Array<Byte>,
    policy!: ContractSshHostVerificationPolicy = ContractSshHostVerificationPolicy()
): ContractSshClientInitialHandshakeResult {
    contractSshCompleteClientInitialHandshakeX25519(
        transcript,
        clientPrivateKey,
        encodedClientInit,
        encodedServerReply,
        negotiated,
        encodedClientNewKeys,
        encodedServerNewKeys,
        policy: policy
    )
}

public func bridgeTrySshCompleteClientInitialHandshakeX25519(
    transcript: SshKexExchangeTranscript,
    clientPrivateKey: Array<Byte>,
    encodedClientInit: Array<Byte>,
    encodedServerReply: Array<Byte>,
    negotiated: SshNegotiatedAlgorithms,
    encodedClientNewKeys: Array<Byte>,
    encodedServerNewKeys: Array<Byte>,
    policy!: ContractSshHostVerificationPolicy = ContractSshHostVerificationPolicy()
): ContractSshClientInitialHandshakeOutcome {
    contractTrySshCompleteClientInitialHandshakeX25519(
        transcript,
        clientPrivateKey,
        encodedClientInit,
        encodedServerReply,
        negotiated,
        encodedClientNewKeys,
        encodedServerNewKeys,
        policy: policy
    )
}

public func bridgeSshCompleteClientInitialHandshakeX25519Request(
    request: BridgeSshClientInitialHandshakeX25519Request
): ContractSshClientInitialHandshakeResult {
    bridgeSshCompleteClientInitialHandshakeX25519(
        bridgeToSshTranscript(request.transcript),
        request.clientPrivateKey,
        request.encodedClientInit,
        request.encodedServerReply,
        bridgeToSshNegotiatedAlgorithms(request.negotiated),
        request.encodedClientNewKeys,
        request.encodedServerNewKeys,
        policy: request.policy
    )
}

public func bridgeTrySshCompleteClientInitialHandshakeX25519Request(
    request: BridgeSshClientInitialHandshakeX25519Request
): ContractSshClientInitialHandshakeOutcome {
    bridgeTrySshCompleteClientInitialHandshakeX25519(
        bridgeToSshTranscript(request.transcript),
        request.clientPrivateKey,
        request.encodedClientInit,
        request.encodedServerReply,
        bridgeToSshNegotiatedAlgorithms(request.negotiated),
        request.encodedClientNewKeys,
        request.encodedServerNewKeys,
        policy: request.policy
    )
}

public func bridgePrepareSshServerRuntimeRequest(
    request: ContractSshServerRuntimeRequest
): ContractSshServerRuntimeBundle {
    contractPrepareSshServerRuntimeRequest(request)
}

public func bridgeTryPrepareSshServerRuntimeRequest(
    request: ContractSshServerRuntimeRequest
): ContractSshServerRuntimeOutcome {
    contractTryPrepareSshServerRuntimeRequest(request)
}

public func bridgePrepareSshClientRuntimeRequest(
    request: ContractSshClientRuntimeRequest
): ContractSshClientRuntimeBundle {
    contractPrepareSshClientRuntimeRequest(request)
}

public func bridgeTryPrepareSshClientRuntimeRequest(
    request: ContractSshClientRuntimeRequest
): ContractSshClientRuntimeOutcome {
    contractTryPrepareSshClientRuntimeRequest(request)
}

public func bridgePrepareSshServerRuntimeRekeyX25519Request(
    request: ContractSshServerRuntimeRekeyRequest
): ContractSshServerRuntimeBundle {
    contractPrepareSshServerRuntimeRekeyX25519Request(request)
}

public func bridgeTryPrepareSshServerRuntimeRekeyX25519Request(
    request: ContractSshServerRuntimeRekeyRequest
): ContractSshServerRuntimeOutcome {
    contractTryPrepareSshServerRuntimeRekeyX25519Request(request)
}

public func bridgePrepareSshClientRuntimeRekeyX25519Request(
    request: ContractSshClientRuntimeRekeyRequest
): ContractSshClientRuntimeBundle {
    contractPrepareSshClientRuntimeRekeyX25519Request(request)
}

public func bridgeTryPrepareSshClientRuntimeRekeyX25519Request(
    request: ContractSshClientRuntimeRekeyRequest
): ContractSshClientRuntimeOutcome {
    contractTryPrepareSshClientRuntimeRekeyX25519Request(request)
}

public func bridgePrepareSshServerRuntimeRekeyFromSessionStateRequest(
    request: ContractSshServerRuntimeSessionRekeyRequest
): ContractSshServerRuntimeBundle {
    contractPrepareSshServerRuntimeRekeyFromSessionStateRequest(request)
}

public func bridgeTryPrepareSshServerRuntimeRekeyFromSessionStateRequest(
    request: ContractSshServerRuntimeSessionRekeyRequest
): ContractSshServerRuntimeOutcome {
    contractTryPrepareSshServerRuntimeRekeyFromSessionStateRequest(request)
}

public func bridgePrepareSshClientRuntimeRekeyFromSessionStateRequest(
    request: ContractSshClientRuntimeSessionRekeyRequest
): ContractSshClientRuntimeBundle {
    contractPrepareSshClientRuntimeRekeyFromSessionStateRequest(request)
}

public func bridgeTryPrepareSshClientRuntimeRekeyFromSessionStateRequest(
    request: ContractSshClientRuntimeSessionRekeyRequest
): ContractSshClientRuntimeOutcome {
    contractTryPrepareSshClientRuntimeRekeyFromSessionStateRequest(request)
}

public func bridgePrepareSshServerLibraryStartupX25519RsaPkcs8Request(
    request: BridgeSshServerLibraryStartupX25519RsaPkcs8Request
): ContractSshServerLibraryStartupBundle {
    contractPrepareSshServerLibraryStartupX25519RsaPkcs8Request(
        ContractSshServerLibraryStartupX25519RsaPkcs8Request(
            bridgeToContractSshTranscript(request.handshake.transcript),
            request.handshake.serverPrivateKey,
            request.handshake.encodedClientInit,
            request.handshake.hostPrivateKeyPkcs8Pem,
            bridgeToContractSshNegotiatedAlgorithms(request.handshake.negotiated),
            request.handshake.encodedClientNewKeys,
            request.handshake.encodedServerNewKeys,
            signatureAlgorithm: request.handshake.signatureAlgorithm,
            serverPublicKey: request.handshake.serverPublicKey,
            profile: request.profile,
            requestedAesEngine: request.requestedAesEngine,
            aesBackendHint: request.aesBackendHint
        )
    )
}

public func bridgeTryPrepareSshServerLibraryStartupX25519RsaPkcs8Request(
    request: BridgeSshServerLibraryStartupX25519RsaPkcs8Request
): ContractSshServerLibraryStartupOutcome {
    contractTryPrepareSshServerLibraryStartupX25519RsaPkcs8Request(
        ContractSshServerLibraryStartupX25519RsaPkcs8Request(
            bridgeToContractSshTranscript(request.handshake.transcript),
            request.handshake.serverPrivateKey,
            request.handshake.encodedClientInit,
            request.handshake.hostPrivateKeyPkcs8Pem,
            bridgeToContractSshNegotiatedAlgorithms(request.handshake.negotiated),
            request.handshake.encodedClientNewKeys,
            request.handshake.encodedServerNewKeys,
            signatureAlgorithm: request.handshake.signatureAlgorithm,
            serverPublicKey: request.handshake.serverPublicKey,
            profile: request.profile,
            requestedAesEngine: request.requestedAesEngine,
            aesBackendHint: request.aesBackendHint
        )
    )
}

public func bridgePrepareSshServerLibraryStartupX25519EcdsaPkcs8Request(
    request: BridgeSshServerLibraryStartupX25519EcdsaPkcs8Request
): ContractSshServerLibraryStartupBundle {
    contractPrepareSshServerLibraryStartupX25519EcdsaPkcs8Request(
        ContractSshServerLibraryStartupX25519EcdsaPkcs8Request(
            bridgeToContractSshTranscript(request.handshake.transcript),
            request.handshake.serverPrivateKey,
            request.handshake.encodedClientInit,
            request.handshake.hostPrivateKeyPkcs8Pem,
            bridgeToContractSshNegotiatedAlgorithms(request.handshake.negotiated),
            request.handshake.encodedClientNewKeys,
            request.handshake.encodedServerNewKeys,
            serverPublicKey: request.handshake.serverPublicKey,
            profile: request.profile,
            requestedAesEngine: request.requestedAesEngine,
            aesBackendHint: request.aesBackendHint
        )
    )
}

public func bridgeTryPrepareSshServerLibraryStartupX25519EcdsaPkcs8Request(
    request: BridgeSshServerLibraryStartupX25519EcdsaPkcs8Request
): ContractSshServerLibraryStartupOutcome {
    contractTryPrepareSshServerLibraryStartupX25519EcdsaPkcs8Request(
        ContractSshServerLibraryStartupX25519EcdsaPkcs8Request(
            bridgeToContractSshTranscript(request.handshake.transcript),
            request.handshake.serverPrivateKey,
            request.handshake.encodedClientInit,
            request.handshake.hostPrivateKeyPkcs8Pem,
            bridgeToContractSshNegotiatedAlgorithms(request.handshake.negotiated),
            request.handshake.encodedClientNewKeys,
            request.handshake.encodedServerNewKeys,
            serverPublicKey: request.handshake.serverPublicKey,
            profile: request.profile,
            requestedAesEngine: request.requestedAesEngine,
            aesBackendHint: request.aesBackendHint
        )
    )
}

public func bridgePrepareSshServerLibraryStartupX25519Ed25519SeedRequest(
    request: BridgeSshServerLibraryStartupX25519Ed25519SeedRequest
): ContractSshServerLibraryStartupBundle {
    contractPrepareSshServerLibraryStartupX25519Ed25519SeedRequest(
        ContractSshServerLibraryStartupX25519Ed25519SeedRequest(
            bridgeToContractSshTranscript(request.handshake.transcript),
            request.handshake.serverPrivateKey,
            request.handshake.encodedClientInit,
            request.handshake.hostPrivateKeySeed,
            bridgeToContractSshNegotiatedAlgorithms(request.handshake.negotiated),
            request.handshake.encodedClientNewKeys,
            request.handshake.encodedServerNewKeys,
            serverPublicKey: request.handshake.serverPublicKey,
            profile: request.profile,
            requestedAesEngine: request.requestedAesEngine,
            aesBackendHint: request.aesBackendHint
        )
    )
}

public func bridgeTryPrepareSshServerLibraryStartupX25519Ed25519SeedRequest(
    request: BridgeSshServerLibraryStartupX25519Ed25519SeedRequest
): ContractSshServerLibraryStartupOutcome {
    contractTryPrepareSshServerLibraryStartupX25519Ed25519SeedRequest(
        ContractSshServerLibraryStartupX25519Ed25519SeedRequest(
            bridgeToContractSshTranscript(request.handshake.transcript),
            request.handshake.serverPrivateKey,
            request.handshake.encodedClientInit,
            request.handshake.hostPrivateKeySeed,
            bridgeToContractSshNegotiatedAlgorithms(request.handshake.negotiated),
            request.handshake.encodedClientNewKeys,
            request.handshake.encodedServerNewKeys,
            serverPublicKey: request.handshake.serverPublicKey,
            profile: request.profile,
            requestedAesEngine: request.requestedAesEngine,
            aesBackendHint: request.aesBackendHint
        )
    )
}

public func bridgePrepareSshClientLibraryStartupX25519Request(
    request: BridgeSshClientLibraryStartupX25519Request
): ContractSshClientLibraryStartupBundle {
    contractPrepareSshClientLibraryStartupX25519Request(
        ContractSshClientLibraryStartupX25519Request(
            ContractSshClientInitialHandshakeX25519Request(
                bridgeToContractSshTranscript(request.handshake.transcript),
                request.handshake.clientPrivateKey,
                request.handshake.encodedClientInit,
                request.handshake.encodedServerReply,
                bridgeToContractSshNegotiatedAlgorithms(request.handshake.negotiated),
                request.handshake.encodedClientNewKeys,
                request.handshake.encodedServerNewKeys,
                policy: request.handshake.policy
            ),
            profile: request.profile,
            requestedAesEngine: request.requestedAesEngine,
            aesBackendHint: request.aesBackendHint
        )
    )
}

public func bridgeTryPrepareSshClientLibraryStartupX25519Request(
    request: BridgeSshClientLibraryStartupX25519Request
): ContractSshClientLibraryStartupOutcome {
    contractTryPrepareSshClientLibraryStartupX25519Request(
        ContractSshClientLibraryStartupX25519Request(
            ContractSshClientInitialHandshakeX25519Request(
                bridgeToContractSshTranscript(request.handshake.transcript),
                request.handshake.clientPrivateKey,
                request.handshake.encodedClientInit,
                request.handshake.encodedServerReply,
                bridgeToContractSshNegotiatedAlgorithms(request.handshake.negotiated),
                request.handshake.encodedClientNewKeys,
                request.handshake.encodedServerNewKeys,
                policy: request.handshake.policy
            ),
            profile: request.profile,
            requestedAesEngine: request.requestedAesEngine,
            aesBackendHint: request.aesBackendHint
        )
    )
}

public func bridgeVerifyHttpClientPeerCertificatePem(
    leafPem: String,
    trustAnchorsPemBundle: String,
    intermediatesPemBundle!: String = "",
    hostname!: String = "",
    validationTime!: String = "",
    pinPolicy!: ContractX509PinPolicy = ContractX509PinPolicy(),
    policy!: ContractTlsHttpNegotiationPolicy = ContractTlsHttpNegotiationPolicy()
): ContractX509VerifyResult {
    contractVerifyHttpClientPeerCertificatePem(
        leafPem,
        trustAnchorsPemBundle,
        intermediatesPemBundle: intermediatesPemBundle,
        hostname: hostname,
        validationTime: validationTime,
        pinPolicy: pinPolicy,
        policy: policy
    )
}

public func bridgeTryVerifyHttpClientPeerCertificatePem(
    leafPem: String,
    trustAnchorsPemBundle: String,
    intermediatesPemBundle!: String = "",
    hostname!: String = "",
    validationTime!: String = "",
    pinPolicy!: ContractX509PinPolicy = ContractX509PinPolicy(),
    policy!: ContractTlsHttpNegotiationPolicy = ContractTlsHttpNegotiationPolicy()
): ContractX509VerifyOutcome {
    contractTryVerifyHttpClientPeerCertificatePem(
        leafPem,
        trustAnchorsPemBundle,
        intermediatesPemBundle: intermediatesPemBundle,
        hostname: hostname,
        validationTime: validationTime,
        pinPolicy: pinPolicy,
        policy: policy
    )
}

public func bridgeVerifyHttpClientPeerCertificateChainPem(
    certificateChainPemBundle: String,
    trustAnchorsPemBundle: String,
    intermediatesPemBundle!: String = "",
    hostname!: String = "",
    validationTime!: String = "",
    pinPolicy!: ContractX509PinPolicy = ContractX509PinPolicy(),
    policy!: ContractTlsHttpNegotiationPolicy = ContractTlsHttpNegotiationPolicy()
): ContractX509VerifyResult {
    contractVerifyHttpClientPeerCertificateChainPem(
        certificateChainPemBundle,
        trustAnchorsPemBundle,
        intermediatesPemBundle: intermediatesPemBundle,
        hostname: hostname,
        validationTime: validationTime,
        pinPolicy: pinPolicy,
        policy: policy
    )
}

public func bridgeTryVerifyHttpClientPeerCertificateChainPem(
    certificateChainPemBundle: String,
    trustAnchorsPemBundle: String,
    intermediatesPemBundle!: String = "",
    hostname!: String = "",
    validationTime!: String = "",
    pinPolicy!: ContractX509PinPolicy = ContractX509PinPolicy(),
    policy!: ContractTlsHttpNegotiationPolicy = ContractTlsHttpNegotiationPolicy()
): ContractX509VerifyOutcome {
    contractTryVerifyHttpClientPeerCertificateChainPem(
        certificateChainPemBundle,
        trustAnchorsPemBundle,
        intermediatesPemBundle: intermediatesPemBundle,
        hostname: hostname,
        validationTime: validationTime,
        pinPolicy: pinPolicy,
        policy: policy
    )
}

private func bridgeToSshTranscript(value: BridgeSshTranscript): SshKexExchangeTranscript {
    SshKexExchangeTranscript(
        value.clientVersionLine,
        value.serverVersionLine,
        value.encodedClientKexInit,
        value.encodedServerKexInit
    )
}

private func bridgeToContractSshTranscript(value: BridgeSshTranscript): ContractSshKexExchangeTranscript {
    ContractSshKexExchangeTranscript(
        value.clientVersionLine,
        value.serverVersionLine,
        value.encodedClientKexInit,
        value.encodedServerKexInit
    )
}

private func bridgeToContractSshNegotiatedAlgorithms(
    value: BridgeSshNegotiatedAlgorithms
): ContractSshNegotiatedAlgorithms {
    ContractSshNegotiatedAlgorithms(
        value.kexAlgorithm,
        value.hostKeyAlgorithm,
        value.clientToServerCipher,
        value.serverToClientCipher,
        value.clientToServerMac,
        value.serverToClientMac,
        compressionAlgorithmClientToServer: value.clientToServerCompression,
        compressionAlgorithmServerToClient: value.serverToClientCompression
    )
}

private func bridgeToSshNegotiatedAlgorithms(value: BridgeSshNegotiatedAlgorithms): SshNegotiatedAlgorithms {
    SshNegotiatedAlgorithms(
        value.kexAlgorithm,
        value.hostKeyAlgorithm,
        value.clientToServerCipher,
        value.serverToClientCipher,
        value.clientToServerMac,
        value.serverToClientMac,
        value.clientToServerCompression,
        value.serverToClientCompression
    )
}

/**
 * bridgeSm3 — SM3 hash (GM/T 0004-2012).
 *
 * @returns 32-byte digest.
 */
public func bridgeSm3(data: Array<Byte>): Array<Byte> {
    sm3(data)
}

/**
 * bridgeSm3Hex — SM3 hash returned as lowercase hex string.
 */
public func bridgeSm3Hex(data: Array<Byte>): String {
    let digest = sm3(data)
    let hexChars: Array<String> = [
        "0", "1", "2", "3", "4", "5", "6", "7",
        "8", "9", "a", "b", "c", "d", "e", "f"
    ]
    var hex = ""
    for (b in digest) {
        let val = Int64(b)
        let hi = hexChars[(val >> 4) & 15]
        let lo = hexChars[val & 15]
        hex = hex + hi + lo
    }
    hex
}

/**
 * bridgeSm4Encrypt — SM4 ECB encrypt (GM/T 0002-2012).
 * key must be 16 bytes, plaintext must be 16 bytes.
 */
public func bridgeSm4Encrypt(
    key: Array<Byte>,
    plaintext: Array<Byte>
): Array<Byte> {
    sm4Encrypt(key, plaintext)
}

/**
 * bridgeSm4Decrypt — SM4 ECB decrypt (GM/T 0002-2012).
 * key must be 16 bytes, ciphertext must be 16 bytes.
 */
public func bridgeSm4Decrypt(
    key: Array<Byte>,
    ciphertext: Array<Byte>
): Array<Byte> {
    sm4Decrypt(key, ciphertext)
}

/**
 * bridgeSmCapability — reports SM3/SM4 availability via contract.
 */
public func bridgeSmCapability(): ContractSmCapability {
    contractSmCapability()
}

/**
 * bridgeTrySmCapability — non-throwing SM capability check.
 */
public func bridgeTrySmCapability(): ContractSmCapabilityOutcome {
    contractTrySmCapability()
}
