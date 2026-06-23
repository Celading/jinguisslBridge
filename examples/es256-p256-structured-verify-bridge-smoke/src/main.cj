package jinguissl_es256_p256_structured_verify_bridge_smoke

import std.collection.ArrayList
import jinguissl_bridge.*

private let STRUCTURED_VERIFY_MESSAGE: String =
    "bridge-es256-p256-structured-verify-smoke"
private let STRUCTURED_VERIFY_PUBLIC_X: String =
    "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
private let STRUCTURED_VERIFY_PUBLIC_Y: String =
    "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
private let STRUCTURED_VERIFY_DER_SIGNATURE: String =
    "3046" + "0221" + "00ca9a117469839d27d6bfa86c53e1d1805ef190aa1e2170388b88c25073dce853" +
    "0221" + "00e250638f8cfb428e23ff5b25ab100890c80e13b2f357b335da9e28ca8fc8a142"

main(): Int64 {
    try {
        runBridgeArtifactDemo()
        runStructuredVerifyBridgeSmoke()
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
}

private func runStructuredVerifyBridgeSmoke(): Unit {
    let signedBytes = STRUCTURED_VERIFY_MESSAGE.toArray()
    let request = BridgeEs256P256StructuredVerifyRequest(
        hexToBytes(STRUCTURED_VERIFY_PUBLIC_X),
        hexToBytes(STRUCTURED_VERIFY_PUBLIC_Y),
        signedBytes,
        hexToBytes(STRUCTURED_VERIFY_DER_SIGNATURE)
    )
    let verified = bridgeTryEs256P256VerifyStructuredRequest(request)
    let tampered = bridgeTryEs256P256VerifyStructured(
        hexToBytes(STRUCTURED_VERIFY_PUBLIC_X),
        hexToBytes(STRUCTURED_VERIFY_PUBLIC_Y),
        "${STRUCTURED_VERIFY_MESSAGE}-tampered".toArray(),
        hexToBytes(STRUCTURED_VERIFY_DER_SIGNATURE)
    )
    let malformed = bridgeTryEs256P256VerifyStructured(
        hexToBytes(STRUCTURED_VERIFY_PUBLIC_X),
        hexToBytes(STRUCTURED_VERIFY_PUBLIC_Y),
        signedBytes,
        [UInt8(0x30), UInt8(0x01), UInt8(0x00)]
    )

    println("== es256-p256-structured-verify-bridge-smoke ==")
    println("structured_message=${STRUCTURED_VERIFY_MESSAGE}")
    println("structured_public_x=${STRUCTURED_VERIFY_PUBLIC_X}")
    println("structured_public_y=${STRUCTURED_VERIFY_PUBLIC_Y}")
    println("structured_verified_ok=${verified.ok}")
    println("structured_verified_message=${verified.message}")
    println("structured_verified_digest_hex=${requireOutcomeDigestHex(verified)}")
    println("structured_signature_verified=${requireOutcomeSignatureVerified(verified)}")
    println("structured_tampered_ok=${tampered.ok}")
    println("structured_tampered_message=${tampered.message}")
    println("structured_tampered_signature_verified=${requireOutcomeSignatureVerified(tampered)}")
    println("structured_malformed_ok=${malformed.ok}")
    println("structured_malformed_message=${malformed.message}")
    println("structured_malformed_code=${requireOutcomeCode(malformed)}")
    println("structured_malformed_ignite_code=${requireOutcomeIgniteCode(malformed)}")
    println("structured_note=bridge consumes already-structured verify input only; parser work and ceremony semantics remain with your upper layer")
}

private func requireOutcomeSignatureVerified(
    outcome: BridgeEs256P256StructuredVerifyOutcome
): Bool {
    match (outcome.result) {
        case Some(value) =>
            value.signatureVerified
        case None =>
            throw Exception("expected structured verify outcome result")
    }
}

private func requireOutcomeDigestHex(
    outcome: BridgeEs256P256StructuredVerifyOutcome
): String {
    match (outcome.result) {
        case Some(value) =>
            bytesToHexLower(value.digestSha256)
        case None =>
            throw Exception("expected structured verify outcome digest")
    }
}

private func requireOutcomeCode(
    outcome: BridgeEs256P256StructuredVerifyOutcome
): String {
    match (outcome.code) {
        case Some(value) =>
            value.toString()
        case None =>
            throw Exception("expected structured verify outcome code")
    }
}

private func requireOutcomeIgniteCode(
    outcome: BridgeEs256P256StructuredVerifyOutcome
): String {
    match (outcome.igniteCode) {
        case Some(value) =>
            value.toString()
        case None =>
            throw Exception("expected structured verify outcome ignite code")
    }
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
