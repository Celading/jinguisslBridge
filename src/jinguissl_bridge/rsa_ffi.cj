package jinguissl_bridge

import std.collection.ArrayList
import std.math.numeric.BigInt
import jinguissl_core.crypto.bignum.BigNum
import jinguissl_core.crypto.error.CryptoException
import jinguissl_core.crypto.rsa.{RsaPublicKey, RsaPrivateKey, rsaSignPkcs1v15, rsaVerifyPkcs1v15}

/**
 * RSA FFI barrier.
 *
 * Return codes:
 *   0  = success
 *  -1  = bad input
 *  -2  = output buffer too small
 *  -3  = crypto / parse error (verify failed)
 *
 * PEM buffers are expected to be null-terminated C strings.
 */

@C
public func rsa_sign_sha256(
    msg: CPointer<UInt8>, msgLen: Int64,
    pem: CPointer<UInt8>, pemLen: Int64,
    sigOut: CPointer<UInt8>, sigOutLen: CPointer<Int64>
): Int32 {
    try {
        unsafe {
            if (msg.isNull() || pem.isNull() || sigOut.isNull() || sigOutLen.isNull()) { return -1 }
            if (msgLen < 0 || pemLen < 1) { return -1 }
            let msgBytes = ptrToBytes(msg, msgLen)
            let pemStr = ptrToString(pem, pemLen)
            let privKey = parseRsaPrivateKeyPkcs8Pem(pemStr)
            let sig = rsaSignPkcs1v15(privKey, msgBytes)
            let sigCapacity = sigOutLen.read()
            if (sigCapacity < 0) { return -1 }
            if (sig.size > sigCapacity) { return -2 }
            bytesToPtr(sig, sigOut)
            sigOutLen.write(sig.size)
            0
        }
    } catch (_: CryptoException) {
        -3
    } catch (_: Exception) {
        -3
    }
}

@C
public func rsa_verify_sha256(
    msg: CPointer<UInt8>, msgLen: Int64,
    sig: CPointer<UInt8>, sigLen: Int64,
    modulus: CPointer<UInt8>, modulusLen: Int64,
    exponent: CPointer<UInt8>, exponentLen: Int64
): Int32 {
    try {
        unsafe {
            if (msg.isNull() || sig.isNull() || modulus.isNull() || exponent.isNull()) { return -1 }
            if (msgLen < 0 || sigLen < 1 || modulusLen < 1 || exponentLen < 1) { return -1 }
            let msgBytes = ptrToBytes(msg, msgLen)
            let sigBytes = ptrToBytes(sig, sigLen)
            let n = BigNum.fromBytesBE(ptrToBytes(modulus, modulusLen))
            let e = BigNum.fromBytesBE(ptrToBytes(exponent, exponentLen))
            let pubKey = RsaPublicKey(n, e)
            if (rsaVerifyPkcs1v15(pubKey, msgBytes, sigBytes)) { 0 } else { -3 }
        }
    } catch (_: CryptoException) {
        -3
    } catch (_: Exception) {
        -3
    }
}

@C
public func rsa_pubkey_from_pkcs8(
    pem: CPointer<UInt8>, pemLen: Int64,
    nOut: CPointer<UInt8>, nOutLen: CPointer<Int64>,
    eOut: CPointer<UInt8>, eOutLen: CPointer<Int64>
): Int32 {
    try {
        unsafe {
            if (pem.isNull() || nOut.isNull() || nOutLen.isNull() || eOut.isNull() || eOutLen.isNull()) { return -1 }
            if (pemLen < 1) { return -1 }
            let pemStr = ptrToString(pem, pemLen)
            let pubKey = parseRsaPublicKeyPem(pemStr)
            let nBytes = pubKey.modulus.toBytesBE()
            let eBytes = pubKey.exponent.toBytesBE()
            let nCapacity = nOutLen.read()
            let eCapacity = eOutLen.read()
            if (nCapacity < 0 || eCapacity < 0) { return -1 }
            if (nBytes.size > nCapacity || eBytes.size > eCapacity) { return -2 }
            bytesToPtr(nBytes, nOut)
            nOutLen.write(nBytes.size)
            bytesToPtr(eBytes, eOut)
            eOutLen.write(eBytes.size)
            0
        }
    } catch (_: CryptoException) {
        -3
    } catch (_: Exception) {
        -3
    }
}

// ---------------------------------------------------------------------------
// PEM parsing helpers  (ASN.1 DER minimal walker for PKCS#8/PKCS#1)
// ---------------------------------------------------------------------------

private func parseRsaPrivateKeyPkcs8Pem(pem: String): RsaPrivateKey {
    let begin = "-----BEGIN PRIVATE KEY-----"
    let end = "-----END PRIVATE KEY-----"
    let der = decodePemBase64(pem, begin, end)
    parsePkcs8PrivateKey(der)
}

private func parseRsaPublicKeyPem(pem: String): RsaPublicKey {
    if (pem.contains("-----BEGIN PUBLIC KEY-----")) {
        let der = decodePemBase64(
            pem,
            "-----BEGIN PUBLIC KEY-----",
            "-----END PUBLIC KEY-----"
        )
        return parseSubjectPublicKeyInfo(der)
    }
    if (pem.contains("-----BEGIN RSA PUBLIC KEY-----")) {
        return parseRsaPublicKeyPkcs1Pem(pem)
    }
    throw Exception("unsupported RSA public key PEM")
}

private func parseRsaPublicKeyPkcs1Pem(pem: String): RsaPublicKey {
    let begin = "-----BEGIN RSA PUBLIC KEY-----"
    let end = "-----END RSA PUBLIC KEY-----"
    let der = decodePemBase64(pem, begin, end)
    parsePkcs1PublicKey(der)
}

private func decodePemBase64(pem: String, beginMarker: String, endMarker: String): Array<Byte> {
    let lines = pem.split("\n")
    var collecting = false
    var b64 = ""
    for (line in lines) {
        let trimmed = line.trimAscii()
        if (trimmed.startsWith(beginMarker)) {
            collecting = true
            continue
        }
        if (trimmed.startsWith(endMarker)) {
            break
        }
        if (collecting) {
            b64 += trimmed
        }
    }
    base64Decode(b64)
}

private func base64Decode(input: String): Array<Byte> {
    let table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=".toRuneArray()
    let runes = input.toRuneArray()
    let out = ArrayList<UInt8>()
    var buffer: Int64 = 0
    var bits: Int64 = 0
    for (ch in runes) {
        if (ch == r'=') { break }
        var value: Int64 = -1
        for (j in 0..64) {
            if (table[j] == ch) { value = j; break }
        }
        if (value < 0) { continue }
        buffer = (buffer << 6) | value
        bits += 6
        if (bits >= 8) {
            bits -= 8
            out.add(UInt8((buffer >> bits) & 0xFF))
        }
    }
    toByteArray(out.toArray())
}

private func toByteArray(bytes: Array<UInt8>): Array<Byte> {
    let out = Array<Byte>(bytes.size, repeat: 0)
    for (i in 0..bytes.size) { out[i] = bytes[i] }
    out
}

private func parsePkcs8PrivateKey(der: Array<Byte>): RsaPrivateKey {
    let rsaDer = extractPkcs8RsaPrivateKey(der)
    parsePkcs1PrivateKey(rsaDer)
}

private func parsePkcs1PrivateKey(der: Array<Byte>): RsaPrivateKey {
    let (values, _) = readSequence(der, 0)
    if (values.size < 9) { throw Exception("invalid PKCS#1 private key") }
    let nInt = asn1IntegerToBigInt(values[1])
    let eInt = asn1IntegerToBigInt(values[2])
    let dInt = asn1IntegerToBigInt(values[3])
    let pubKey = RsaPublicKey(BigNum(nInt), BigNum(eInt))
    RsaPrivateKey(BigNum(nInt), BigNum(eInt), BigNum(dInt))
}

private func parsePkcs1PublicKey(der: Array<Byte>): RsaPublicKey {
    let (values, _) = readSequence(der, 0)
    if (values.size < 2) { throw Exception("invalid PKCS#1 public key") }
    let nInt = asn1IntegerToBigInt(values[0])
    let eInt = asn1IntegerToBigInt(values[1])
    RsaPublicKey(BigNum(nInt), BigNum(eInt))
}

private func parseSubjectPublicKeyInfo(der: Array<Byte>): RsaPublicKey {
    let (values, end) = readTaggedSequence(der, 0)
    if (end != der.size || values.size < 2) {
        throw Exception("invalid PKCS#8 public key")
    }
    if (values[0].tag != 0x30 || values[1].tag != 0x03) {
        throw Exception("invalid PKCS#8 public key layout")
    }
    if (!isRsaEncryptionAlgorithmIdentifierBody(values[0].value)) {
        throw Exception("unsupported PKCS#8 public key algorithm")
    }
    let bitString = values[1].value
    if (bitString.size < 2 || UInt8(bitString[0]) != UInt8(0)) {
        throw Exception("invalid PKCS#8 public key bit string")
    }
    parsePkcs1PublicKey(bitString[1..])
}

private func isRsaEncryptionAlgorithmIdentifierBody(bytes: Array<Byte>): Bool {
    if (bytes.size != 11 && bytes.size != 13) {
        return false
    }
    let rsaEncryptionOid = [
        UInt8(0x06), UInt8(0x09), UInt8(0x2A), UInt8(0x86),
        UInt8(0x48), UInt8(0x86), UInt8(0xF7), UInt8(0x0D),
        UInt8(0x01), UInt8(0x01), UInt8(0x01)
    ]
    for (i in 0..rsaEncryptionOid.size) {
        if (UInt8(bytes[i]) != rsaEncryptionOid[i]) {
            return false
        }
    }
    if (bytes.size == 13) {
        return UInt8(bytes[11]) == UInt8(0x05) && UInt8(bytes[12]) == UInt8(0)
    }
    true
}

private func extractPkcs8RsaPrivateKey(der: Array<Byte>): Array<Byte> {
    var pos: Int64 = 0
    let (_, outerLen) = readTag(der, pos)
    pos = outerLen
    pos = skipInteger(der, pos)
    let (_, algoEnd) = readTag(der, pos)
    pos = algoEnd
    if (pos >= der.size || der[pos] != 0x04) { throw Exception("expected OCTET STRING in PKCS#8") }
    pos += 1
    let (octetLen, _) = readLength(der, pos)
    pos = skipLength(der, pos)
    if (pos + octetLen > der.size) { throw Exception("PKCS#8 octet string exceeds DER") }
    der[pos..pos + octetLen]
}

private func skipInteger(der: Array<Byte>, pos: Int64): Int64 {
    if (pos >= der.size || der[pos] != 0x02) { throw Exception("expected INTEGER") }
    var p = pos + 1
    let (len, _) = readLength(der, p)
    p = skipLength(der, p)
    p + len
}

private func readTag(der: Array<Byte>, pos: Int64): (Int64, Int64) {
    if (pos >= der.size) { throw Exception("unexpected end of DER") }
    let tag = Int64(UInt8(der[pos]))
    var p = pos + 1
    let (len, _) = readLength(der, p)
    p = skipLength(der, p)
    (tag, p + len)
}

private func readSequence(der: Array<Byte>, pos: Int64): (ArrayList<Array<Byte>>, Int64) {
    if (pos >= der.size || der[pos] != 0x30) { throw Exception("expected SEQUENCE") }
    var p = pos + 1
    let (totalLen, _) = readLength(der, p)
    p = skipLength(der, p)
    let end = p + totalLen
    let values = ArrayList<Array<Byte>>()
    while (p < end) {
        let tag = Int64(UInt8(der[p]))
        let contentStart = p + 1
        let (contentLen, _) = readLength(der, contentStart)
        p = skipLength(der, contentStart)
        values.add(der[p..p + contentLen])
        p += contentLen
    }
    (values, end)
}

private class Asn1Element {
    let tag: Int64
    let value: Array<Byte>

    init(tag: Int64, value: Array<Byte>) {
        this.tag = tag
        this.value = value.clone()
    }
}

private func readTaggedSequence(der: Array<Byte>, pos: Int64): (ArrayList<Asn1Element>, Int64) {
    if (pos >= der.size || der[pos] != 0x30) { throw Exception("expected SEQUENCE") }
    var p = pos + 1
    let (totalLen, _) = readLength(der, p)
    p = skipLength(der, p)
    let end = p + totalLen
    if (end > der.size) { throw Exception("SEQUENCE length exceeds DER") }
    let values = ArrayList<Asn1Element>()
    while (p < end) {
        let tag = Int64(UInt8(der[p]))
        let contentStart = p + 1
        let (contentLen, _) = readLength(der, contentStart)
        p = skipLength(der, contentStart)
        if (p + contentLen > end) { throw Exception("SEQUENCE element length exceeds DER") }
        values.add(Asn1Element(tag, der[p..p + contentLen]))
        p += contentLen
    }
    (values, end)
}

private func readLength(der: Array<Byte>, pos: Int64): (Int64, Int64) {
    if (pos >= der.size) { throw Exception("unexpected end of DER in length") }
    let first = UInt8(der[pos])
    if (Int64(first) < 0x80) {
        return (Int64(first), 1)
    }
    let numBytes = Int64(first) & 0x7F
    if (numBytes == 0 || numBytes > 4) { throw Exception("unsupported DER length encoding") }
    var len: Int64 = 0
    for (i in 1..numBytes + 1) {
        if (pos + i >= der.size) { throw Exception("unexpected end of DER in long length") }
        len = (len << 8) + Int64(UInt8(der[pos + i]))
    }
    (len, numBytes + 1)
}

private func skipLength(der: Array<Byte>, pos: Int64): Int64 {
    let (_, bytesConsumed) = readLength(der, pos)
    pos + bytesConsumed
}

private func asn1IntegerToBigInt(bytes: Array<Byte>): BigInt {
    if (bytes.size == 0) { return BigInt(0) }
    let isNeg = (UInt8(bytes[0]) & 0x80) != 0
    if (isNeg) {
        var inverted = Array<Byte>(bytes.size, repeat: 0)
        for (i in 0..bytes.size) { inverted[i] = UInt8(255 - UInt8(bytes[i])) }
        let pos = BigInt(true, inverted) + BigInt(1)
        -pos
    } else {
        BigInt(true, bytes)
    }
}

// ---------------------------------------------------------------------------
// CPointer <-> String / Array<Byte>
// ---------------------------------------------------------------------------

private func ptrToBytes(ptr: CPointer<UInt8>, len: Int64): Array<Byte> {
    if (len == 0) { return [] }
    unsafe {
        let out = ArrayList<Byte>()
        for (i in 0..len) {
            let val = ptr.read(i)
            out.add(val)
        }
        out.toArray()
    }
}

private func bytesToPtr(bytes: Array<Byte>, ptr: CPointer<UInt8>): Unit {
    unsafe {
        for (i in 0..bytes.size) {
            ptr.write(i, UInt8(bytes[i]))
        }
    }
}

private func ptrToString(ptr: CPointer<UInt8>, len: Int64): String {
    let bytes = ptrToBytes(ptr, len)
    var out = ""
    for (b in bytes) {
        if (b == 0) { break }
        out += Rune(UInt8(b)).toString()
    }
    out
}
