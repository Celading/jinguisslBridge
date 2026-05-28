package jinguissl_http_client_tls_bridge_smoke

import std.collection.ArrayList
import std.fs.File
import jinguissl_bridge.*

main(): Int64 {
    try {
        runBridgeArtifactDemo()
        runHttpClientGateAndStartupDemo()
        runHttpClientTlsBridgeSmoke()
        0
    } catch (e: Exception) {
        println("fatal=${e}")
        1
    }
}

private func runBridgeArtifactDemo(): Unit {
    let artifact = bridgeArtifactInfo()

    println("== bridge-artifact ==")
    println("bridge_package=${artifact.packageName}")
    println("bridge_output_type=${artifact.outputType}")
    println("bridge_facade_import=${artifact.facadeImportPath}")
    println("bridge_direct_stdx_tls_bridge=${artifact.directStdxTlsServerConfigBridge}")
    println("bridge_note_count=${artifact.notes.size}")
}

private func runHttpClientGateAndStartupDemo(): Unit {
    let serverName = "www.example.com"
    let rootPem = readText("../../../testdata/x509/policy_root.pem")
    let intermediatePem = readText("../../../testdata/x509/policy_intermediate.pem")
    let gates = bridgeListProviderConsumptionGates()
    var gateIndex = -1
    var i = 0
    while (i < gates.size) {
        if (gates[i].guide.label == "http-client-tls") {
            gateIndex = i
            break
        }
        i += 1
    }
    if (gateIndex < 0) {
        throw Exception("expected HTTP_CLIENT_TLS gate report")
    }
    let gate = gates[gateIndex]
    let trustRequest = BridgeHttpClientTlsTrustRequest(
        rootPem,
        intermediatesPemBundle: intermediatePem,
        hostname: serverName,
        validationTime: "230101000000Z"
    )
    let trustValidation = bridgeValidateHttpClientTlsTrustRequest(trustRequest)
    let trustMaterial = bridgePrepareHttpClientTlsTrustMaterialRequest(trustRequest)
    let clientBundle = bridgePrepareHttpClientLibraryStartupRequest(
        BridgeHttpClientLibraryStartupRequest(
            trustRequest,
            aesBackendHint: "shim"
        )
    )
    let smokeLabel = match (gate.smokeProfile) {
        case Some(value) => value.label
        case None => "NONE"
    }
    let smokeReady = match (gate.smokeReadiness) {
        case Some(value) => value.overallReady
        case None => false
    }

    println("== http-client-bridge-gate-startup ==")
    println("gate_public_path=${gate.publicPath}")
    println("gate_status=${gate.status}")
    println("gate_selected_entry=${gate.selectedEntryId}")
    println("gate_release_path=${gate.releasePath}")
    println("gate_risk_level=${gate.riskLevel}")
    println("gate_ready_now=${gate.readyNow}")
    println("gate_fallback_target=${gate.fallbackTarget}")
    println("gate_candidate_order=${joinStrings(gate.candidateOrder)}")
    println("gate_observability_tags=${joinStrings(gate.observabilityTags)}")
    println("gate_smoke_profile=${smokeLabel}")
    println("gate_smoke_ready=${smokeReady}")
    println("trust_hostname=${trustValidation.normalizedHostname}")
    println(
        "trust_alpn_preference=${joinStrings(trustValidation.negotiationPolicy.normalizedAlpnPreference)}"
    )
    println("trust_anchor_count=${trustValidation.trustAnchorCount}")
    println("trust_intermediate_count=${trustMaterial.intermediatePemBlocks.size}")
    println("startup_profile=${clientBundle.template.label}")
    println("startup_http_tls_ready=${clientBundle.readiness.httpTlsReady}")
    println("startup_overall_ready=${clientBundle.readiness.overallReady}")
    println("startup_aes_backend=${clientBundle.readiness.aes.selectedEngine.backend}")
    println("startup_primary_backend=${clientBundle.readiness.aesCurrentReleasePlan.primaryBackend}")
    println(
        "gate_note=bridge keeps HTTP client gate and startup facts on one import surface; this remains provider-candidate guidance, not default HTTPS attach"
    )
}

private func runHttpClientTlsBridgeSmoke(): Unit {
    let serverName = "www.example.com"
    let alpnProtocols = ["h2", "http/1.1"]
    let leafPem = readText("../../../testdata/x509/policy_leaf.pem")
    let intermediatePem = readText("../../../testdata/x509/policy_intermediate.pem")
    let rootPem = readText("../../../testdata/x509/policy_root.pem")
    let leafKeyPem = readText("../../../testdata/x509/policy_leaf_key_pkcs8.pem")
    let clientHello = bridgeTls13BuildHttpClientHelloX25519Request(
        BridgeTls13HttpClientHelloX25519Request(
            serverName,
            alpnProtocols: alpnProtocols,
            clientPrivateKey: Some(incrementalBytes(32, start: 48))
        )
    )
    let serverFlight = bridgeTls13BuildHttpServerFlightX25519Request(
        BridgeTls13HttpServerFlightX25519Request(
            clientHello.encodedClientHello,
            incrementalBytes(32, start: 80),
            "${leafPem}\n${intermediatePem}",
            leafKeyPem
        )
    )
    let trustRequest = BridgeHttpClientTlsTrustRequest(
        rootPem,
        intermediatesPemBundle: intermediatePem,
        hostname: serverName,
        validationTime: "230101000000Z"
    )
    let verified = bridgeTryTls13VerifyHttpServerFlightX25519WithSessionRequest(
        BridgeTls13HttpVerifyServerFlightX25519Request(
            clientHello,
            serverFlight,
            trustRequest
        )
    )
    let verifiedSession = match (verified.result) {
        case Some(value) => value
        case None => throw Exception("expected verified session bridge outcome result")
    }
    let cipherBinding = bridgeTls13ResolveCipherBindingFromVerifiedSession(verifiedSession)
    let runtime = bridgeTls13CreateVerifiedSessionChannelSetRequest(
        BridgeTls13HttpVerifiedSessionRequest(verifiedSession)
    )
    let ciphertext = runtime.clientChannel.sealApplicationData(
        "bridge-http-client-payload".toArray()
    )
    let opened = runtime.serverChannel.openApplicationData(ciphertext)
    let exporter = bridgeTls13ExportKeyingMaterialFromVerifiedSessionRequest(
        BridgeTls13HttpVerifiedSessionExportRequest(
            verifiedSession,
            "bridge/http-client-smoke"
        )
    )
    let localTrafficUpdate = bridgeTls13RotateClientTrafficInVerifiedSessionRequest(
        BridgeTls13HttpVerifiedSessionKeyUpdateRequest(
            verifiedSession,
            requestPeerUpdate: true
        )
    )
    let peerTrafficUpdate = bridgeTls13ApplyPeerTrafficUpdateToVerifiedSessionRequest(
        BridgeTls13HttpVerifiedSessionPeerKeyUpdateRequest(
            verifiedSession,
            localTrafficUpdate.encodedKeyUpdate
        )
    )
    let peerCiphertext = peerTrafficUpdate.runtime.serverChannel.sealApplicationData(
        "bridge-http-client-peer-update".toArray()
    )
    let peerOpened = peerTrafficUpdate.runtime.clientChannel.openApplicationData(peerCiphertext)
    let encryptedCloseNotify = runtime.clientChannel.sendCloseNotify()
    let decodedCloseNotify = runtime.serverChannel.openAlert(encryptedCloseNotify)
    let failed = bridgeTryTls13VerifyHttpServerFlightX25519Request(
        BridgeTls13HttpVerifyServerFlightX25519Request(
            clientHello,
            serverFlight,
            BridgeHttpClientTlsTrustRequest(
                rootPem,
                intermediatesPemBundle: intermediatePem,
                hostname: "api.example.com",
                validationTime: "230101000000Z"
            )
        )
    )
    let failedCode = match (failed.code) {
        case Some(value) => value.toString()
        case None => "NONE"
    }
    let failedIgniteCode = match (failed.igniteCode) {
        case Some(value) => value.toString()
        case None => "NONE"
    }

    println("== http-client-tls-bridge-smoke ==")
    println("tls_client_hello_len=${clientHello.encodedClientHello.size}")
    println("tls_client_hello_prefix_hex=${hexPrefix(clientHello.encodedClientHello, 24)}")
    println("tls_server_hello_len=${serverFlight.serverHello.size}")
    println("tls_verify_ok=${verified.ok}")
    println("tls_verify_message=${verified.message}")
    println("tls_selected_alpn=${verifiedSession.result.selectedAlpn}")
    println("tls_chain_length=${verifiedSession.result.chainLength}")
    println("tls_leaf_common_name=${verifiedSession.result.leafSubjectCommonName}")
    println("tls_cipher_suite=${cipherBinding.cipherSuiteName}")
    println("tls_runtime_payload=${String.fromUtf8(opened)}")
    println("tls_exporter_len=${exporter.size}")
    println("tls_exporter_prefix_hex=${hexPrefix(exporter, 16)}")
    println("tls_key_update_len=${localTrafficUpdate.encodedKeyUpdate.size}")
    println("tls_peer_update_payload=${String.fromUtf8(peerOpened)}")
    println("tls_close_notify=${decodedCloseNotify.isCloseNotify}")
    println("tls_failed_ok=${failed.ok}")
    println("tls_failed_message=${failed.message}")
    println("tls_failed_code=${failedCode}")
    println("tls_failed_ignite_code=${failedIgniteCode}")
    println(
        "tls_note=bridge covers trust/startup/verified-session continuation on one import surface; raw socket framing and fallback orchestration remain with your upper layer"
    )
}

private func joinStrings(values: Array<String>): String {
    var out = ""
    var i = 0
    while (i < values.size) {
        if (i > 0) {
            out += ","
        }
        out += values[i]
        i += 1
    }
    out
}

private func incrementalBytes(size: Int64, start!: Int64 = 0): Array<Byte> {
    let out = Array<Byte>(size, repeat: 0)
    var i = 0
    while (i < size) {
        out[i] = UInt8((start + i) & 0xff)
        i += 1
    }
    out
}

private func hexPrefix(bytes: Array<Byte>, limitBytes: Int64): String {
    let clamped = if (bytes.size < limitBytes) { bytes.size } else { limitBytes }
    let prefix = Array<Byte>(clamped, repeat: 0)
    var i = 0
    while (i < clamped) {
        prefix[i] = bytes[i]
        i += 1
    }
    let rendered = bytesToHexLower(prefix)
    if (clamped == bytes.size) {
        return rendered
    }
    "${rendered}..."
}

private func bytesToHexLower(bytes: Array<Byte>): String {
    let out = ArrayList<Byte>()
    for (value in bytes) {
        let current = UInt8(value)
        out.add(hexNibbleLower((Int64(current) >> 4) & 0xf))
        out.add(hexNibbleLower(Int64(current) & 0xf))
    }
    String.fromUtf8(out.toArray())
}

private func hexNibbleLower(value: Int64): Byte {
    if (value < 10) {
        return UInt8(Int64(b'0') + value)
    }
    UInt8(Int64(b'a') + (value - 10))
}

private func readText(path: String): String {
    String.fromUtf8(File.readFrom(path))
}
