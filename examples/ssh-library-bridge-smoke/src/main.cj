package jinguissl_ssh_library_bridge_smoke

import std.collection.ArrayList
import jinguissl_bridge.*

main(): Int64 {
    try {
        runBridgeArtifactDemo()
        runSshLibraryBridgeSmoke()
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

private func runSshLibraryBridgeSmoke(): Unit {
    let transcript = BridgeSshTranscript(
        "SSH-2.0-jinguiSSL-bridge-client library-bridge-smoke\r\n".toArray(),
        "SSH-2.0-jinguiSSL-bridge-server library-bridge-smoke\r\n".toArray(),
        bridgeSshBuildDefaultKexInitPacket(cookie: incrementalBytes(16, start: 32)),
        bridgeSshBuildDefaultKexInitPacket(cookie: incrementalBytes(16, start: 64))
    )
    let negotiated = BridgeSshNegotiatedAlgorithms(
        "curve25519-sha256",
        "ssh-ed25519",
        "aes128-ctr",
        "aes128-ctr",
        "hmac-sha2-256",
        "hmac-sha2-256",
        clientToServerCompression: "none",
        serverToClientCompression: "none"
    )
    let clientPrivate = hexToBytes(
        "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
    )
    let serverPrivate = hexToBytes(
        "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"
    )
    let ed25519Seed = hexToBytes(
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
    )
    let initResult = bridgeSshBuildKexEcdhInitX25519(clientPrivate)
    let encodedClientNewKeys = bridgeSshEncodeNewKeys()
    let encodedServerNewKeys = bridgeSshEncodeNewKeys()
    let serverBundle = bridgePrepareSshServerLibraryStartupX25519Ed25519SeedRequest(
        BridgeSshServerLibraryStartupX25519Ed25519SeedRequest(
            BridgeSshServerInitialHandshakeX25519Ed25519SeedRequest(
                transcript,
                serverPrivate,
                initResult.encodedClientInit,
                ed25519Seed,
                negotiated,
                encodedClientNewKeys,
                encodedServerNewKeys
            ),
            aesBackendHint: "shim"
        )
    )
    let clientBundle = bridgePrepareSshClientLibraryStartupX25519Request(
        BridgeSshClientLibraryStartupX25519Request(
            BridgeSshClientInitialHandshakeX25519Request(
                transcript,
                clientPrivate,
                initResult.encodedClientInit,
                serverBundle.handshake.encodedReply,
                negotiated,
                encodedClientNewKeys,
                encodedServerNewKeys
            ),
            aesBackendHint: "shim"
        )
    )
    let verification = clientBundle.handshake.requireHostVerification()
    let clientPacket = clientBundle.runtime.seal(
        "bridge-ssh-client-payload".toArray(),
        randomPadding: incrementalBytes(48, start: 96)
    )
    let serverOpened = serverBundle.runtime.open(clientPacket)
    let serverPacket = serverBundle.runtime.seal(
        "bridge-ssh-server-payload".toArray(),
        randomPadding: incrementalBytes(48, start: 160)
    )
    let clientOpened = clientBundle.runtime.open(serverPacket)

    println("== ssh-library-bridge-smoke ==")
    println("ssh_client_version_line=${String.fromUtf8(transcript.clientVersionLine)}")
    println("ssh_server_version_line=${String.fromUtf8(transcript.serverVersionLine)}")
    println("ssh_negotiated_kex=${negotiated.kexAlgorithm}")
    println("ssh_negotiated_hostkey=${negotiated.hostKeyAlgorithm}")
    println("ssh_server_profile=${serverBundle.template.label}")
    println("ssh_client_profile=${clientBundle.template.label}")
    println("ssh_server_ready=${serverBundle.readiness.overallReady}")
    println("ssh_client_ready=${clientBundle.readiness.overallReady}")
    println("ssh_host_signature_verified=${verification.hostSignatureVerified}")
    println("ssh_session_id_hex=${bytesToHexLower(clientBundle.handshake.sessionId)}")
    println("ssh_host_key_sha256_hex=${bytesToHexLower(serverBundle.handshake.hostKeySha256)}")
    println("ssh_client_packet_len=${clientPacket.size}")
    println("ssh_server_opened_payload=${String.fromUtf8(serverOpened.payload)}")
    println("ssh_server_packet_len=${serverPacket.size}")
    println("ssh_client_opened_payload=${String.fromUtf8(clientOpened.payload)}")
    println("ssh_note=bridge wrappers cover startup input shaping and runtime bundle handoff; banner exchange, packet IO, and later orchestration remain with your upper layer")
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

private func hexToBytes(hex: String): Array<Byte> {
    let normalized = hex.trimAscii()
    if ((normalized.size % 2) != 0) {
        throw Exception("hex string length must be even")
    }
    let bytes = normalized.toArray()
    let out = ArrayList<Byte>()
    var i = 0
    while (i < normalized.size) {
        out.add(UInt8(parseHexByte(UInt8(bytes[i]), UInt8(bytes[i + 1]))))
        i += 2
    }
    out.toArray()
}

private func parseHexByte(high: UInt8, low: UInt8): Int64 {
    (parseHexNibble(high) << 4) | parseHexNibble(low)
}

private func parseHexNibble(ch: UInt8): Int64 {
    if (ch >= b'0' && ch <= b'9') {
        return Int64(ch) - Int64(b'0')
    }
    let lower = if (ch >= b'A' && ch <= b'F') { ch + UInt8(32) } else { ch }
    if (lower >= b'a' && lower <= b'f') {
        return Int64(lower) - Int64(b'a') + 10
    }
    throw Exception("invalid hex digit")
}
