package jinguissl_http_server_attach_planning_bridge_smoke

import std.collection.ArrayList
import std.fs.File
import jinguissl_bridge.*

private let TEST_HOST_WWW: String = "www." + "example.com"

main(): Int64 {
    try {
        runBridgeArtifactDemo()
        runHttpServerPlanningGateDemo()
        runHttpServerPlanningMaterialDemo()
        runHttpServerAttachPlanDemo()
        runHttpServerAttachResultDemo()
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

private func runHttpServerPlanningGateDemo(): Unit {
    let gates = bridgeListProviderConsumptionGates()
    var planningIndex = -1
    var stableIndex = -1
    var i = 0
    while (i < gates.size) {
        if (gates[i].guide.label == "http-server-attach-planning") {
            planningIndex = i
        }
        if (gates[i].guide.label == "http-server-stable-attach") {
            stableIndex = i
        }
        i += 1
    }
    if (planningIndex < 0 || stableIndex < 0) {
        throw Exception("expected HTTP server planning/stable gates")
    }
    let planningGate = gates[planningIndex]
    let stableGate = gates[stableIndex]

    println("== http-server-planning-bridge-gate ==")
    println("planning_status=${planningGate.status}")
    println("planning_selected_entry=${planningGate.selectedEntryId}")
    println("planning_public_path=${planningGate.publicPath}")
    println("planning_release_path=${planningGate.releasePath}")
    println("planning_ready_now=${planningGate.readyNow}")
    println("planning_candidate_order=${joinStrings(planningGate.candidateOrder)}")
    println("planning_observability_tags=${joinStrings(planningGate.observabilityTags)}")
    println("planning_attach_meaning=${planningGate.guide.attachPlanMeaning}")
    println("planning_selected_reason=${planningGate.selectedReason}")
    println("boundary_status=${planningGate.attachBoundary.status}")
    println("boundary_stable_attach=${planningGate.attachBoundary.stableAttach}")
    println("boundary_blocking_layer=${planningGate.attachBoundary.blockingLayer}")
    println("boundary_recommended_fallback=${planningGate.attachBoundary.recommendedFallback}")
    println("stable_attach_status=${stableGate.status}")
    println("stable_attach_public_path=${stableGate.publicPath}")
    println("stable_attach_ready_now=${stableGate.readyNow}")
    println("stable_attach_blocked=${joinStrings(stableGate.blockedCandidates)}")
    println(
        "planning_note=planning-only means the bridge may validate config, normalize TLS material, and expose startup facts now, but final listener attach still stops in upper-layer glue"
    )
}

private func runHttpServerPlanningMaterialDemo(): Unit {
    let leafPem = readText("../../testdata/x509/policy_leaf.pem")
    let intermediatePem = readText("../../testdata/x509/policy_intermediate.pem")
    let certChainPem = "${leafPem}\n${intermediatePem}"
    let leafKeyPem = readText("../../testdata/x509/policy_leaf_key_pkcs8.pem")
    let wrongKeyPem = readText("../../testdata/x509/rsa_2048_pkcs8.pem")

    let request = BridgeHttpServerTlsConfigRequest(
        certChainPem,
        leafKeyPem,
        alpnProtocols: [" H2 ", "http/1.1", "h2"],
        requireHttp2Alpn: true
    )
    let validated = bridgeValidateHttpServerTlsConfigRequest(request)
    let prepared = bridgePrepareHttpServerTlsMaterialRequest(request)
    let startupBundle = bridgePrepareHttpServerLibraryStartupRequest(
        BridgeHttpServerLibraryStartupRequest(
            request,
            aesBackendHint: "shim"
        )
    )
    let missingH2Outcome = bridgeTryPrepareHttpServerTlsMaterialRequest(
        BridgeHttpServerTlsConfigRequest(
            certChainPem,
            leafKeyPem,
            alpnProtocols: ["http/1.1"],
            requireHttp2Alpn: true
        )
    )
    let mismatchOutcome = bridgeTryPrepareHttpServerTlsMaterialRequest(
        BridgeHttpServerTlsConfigRequest(
            certChainPem,
            wrongKeyPem,
            alpnProtocols: ["h2", "http/1.1"],
            requireHttp2Alpn: true
        )
    )
    let missingH2Code = match (missingH2Outcome.code) {
        case Some(value) => value.toString()
        case None => "NONE"
    }
    let mismatchCode = match (mismatchOutcome.code) {
        case Some(value) => value.toString()
        case None => "NONE"
    }
    let leafPemPresent = prepared.leafCertificatePem().contains("BEGIN CERTIFICATE")
    let bundlePemPresent = prepared.certificateChainPemBundle().contains("BEGIN CERTIFICATE")
    let privateKeyPresent = prepared.privateKeyPem.contains("BEGIN PRIVATE KEY")

    println("== http-server-planning-bridge-material ==")
    println("validation_chain_length=${validated.certificateChainLength}")
    println("validation_leaf_cn=${validated.leafSubjectCommonName}")
    println("validation_issuer_cn=${validated.leafIssuerCommonName}")
    println("validation_key_algorithm=${validated.keyAlgorithm}")
    println("validation_normalized_alpn=${joinStrings(validated.normalizedAlpnProtocols)}")
    println("material_pem_block_count=${prepared.certificateChainPemBlocks.size}")
    println("material_leaf_pem_present=${leafPemPresent}")
    println("material_bundle_present=${bundlePemPresent}")
    println("material_private_key_present=${privateKeyPresent}")
    println("startup_profile=${startupBundle.template.label}")
    println("startup_http_tls_ready=${startupBundle.readiness.httpTlsReady}")
    println("startup_overall_ready=${startupBundle.readiness.overallReady}")
    println("startup_aes_backend=${startupBundle.readiness.aes.selectedEngine.backend}")
    println("startup_primary_backend=${startupBundle.readiness.aesCurrentReleasePlan.primaryBackend}")
    println("missing_h2_ok=${missingH2Outcome.ok}")
    println("missing_h2_code=${missingH2Code}")
    println("key_mismatch_ok=${mismatchOutcome.ok}")
    println("key_mismatch_code=${mismatchCode}")
    println(
        "material_note=successful preparation gives upper layers normalized TLS material and startup readiness on the bridge surface, but it still does not publish a stable listener attach contract"
    )
}

private func runHttpServerAttachPlanDemo(): Unit {
    let leafPem = readText("../../testdata/x509/policy_leaf.pem")
    let intermediatePem = readText("../../testdata/x509/policy_intermediate.pem")
    let certChainPem = "${leafPem}\n${intermediatePem}"
    let leafKeyPem = readText("../../testdata/x509/policy_leaf_key_pkcs8.pem")

    let plan = bridgePlanHttpServerAttach(
        certChainPem,
        leafKeyPem,
        alpnProtocols: [" H2 ", "http/1.1", "h2"],
        requireHttp2Alpn: true,
        aesBackendHint: "shim"
    )

    println("== http-server-attach-plan ==")
    println("attach_surface=${plan.attachSurface}")
    println("attach_listener_owned=${plan.listenerOwned}")
    println("attach_expected_tls=${plan.expectedTlsVersion}")
    println("attach_expected_alpn=${joinStrings(plan.expectedAlpnProtocols)}")
    println("attach_planning_gate=${plan.planningGate.status}")
    println("attach_stable_gate=${plan.stableAttachGate.status}")
    println("attach_material_key_algorithm=${plan.startup.material.validation.keyAlgorithm}")
    println(
        "attach_plan_note=accepted-socket planning is now a typed bridge surface, while real socket IO remains a later attach lifecycle packet"
    )
}

private func runHttpServerAttachResultDemo(): Unit {
    let serverName = TEST_HOST_WWW
    let alpnProtocols = ["h2", "http/1.1"]
    let leafPem = readText("../../testdata/x509/policy_leaf.pem")
    let intermediatePem = readText("../../testdata/x509/policy_intermediate.pem")
    let leafKeyPem = readText("../../testdata/x509/policy_leaf_key_pkcs8.pem")
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
    let result = bridgeBuildHttpServerAttachResultFromTls13Flight(serverFlight)

    println("== http-server-attach-result ==")
    println("attach_result_surface=${result.attachSurface}")
    println("attach_result_tls=${result.tlsVersion}")
    println("attach_result_cipher=${result.cipherSuite}")
    println("attach_result_alpn=${result.negotiatedAlpn}")
    println("attach_result_sni=${result.requestedServerName}")
    println("attach_result_sni_ack=${result.acknowledgedServerName}")
    println("attach_result_secure_session_ready=${result.secureSessionReady}")
    println(
        "attach_result_note=TLS1.3 server-flight metadata is now lifted to a bridge-facing attach result; socket IO is still intentionally not claimed"
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

private func readText(path: String): String {
    String.fromUtf8(File.readFrom(path))
}
