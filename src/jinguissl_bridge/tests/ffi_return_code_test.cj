package jinguissl_bridge.tests

import jinguissl_bridge.*

@Test
public class BridgeFfiReturnCodeTest {
    @TestCase
    public func testNullInputsReturnBadInput(): Unit {
        let bytes = CPointer<UInt8>()
        let len = CPointer<Int64>()

        let initStatus = unsafe { bridge_ffi_init(bytes, len) }
        let edSignStatus = unsafe { ed25519_sign(bytes, 0, bytes, 0, bytes, len) }
        let edVerifyStatus = unsafe { ed25519_verify(bytes, 0, bytes, 0, bytes, 0) }
        let edPubStatus = unsafe { ed25519_pubkey_from_seed(bytes, 0, bytes, len) }
        let eccSignStatus = unsafe { ecc_p256_sign(bytes, 0, bytes, 0, bytes, len, bytes, len) }
        let eccVerifyStatus = unsafe { ecc_p256_verify(bytes, 0, bytes, 0, bytes, 0, bytes, 0, bytes, 0) }
        let eccPubStatus = unsafe { ecc_p256_pubkey_from_scalar(bytes, 0, bytes, len, bytes, len) }
        let rsaSignStatus = unsafe { rsa_sign_sha256(bytes, 0, bytes, 0, bytes, len) }
        let rsaVerifyStatus = unsafe { rsa_verify_sha256(bytes, 0, bytes, 0, bytes, 0, bytes, 0) }
        let rsaPubStatus = unsafe { rsa_pubkey_from_pkcs8(bytes, 0, bytes, len, bytes, len) }

        @Assert(initStatus, -1)
        @Assert(edSignStatus, -1)
        @Assert(edVerifyStatus, -1)
        @Assert(edPubStatus, -1)
        @Assert(eccSignStatus, -1)
        @Assert(eccVerifyStatus, -1)
        @Assert(eccPubStatus, -1)
        @Assert(rsaSignStatus, -1)
        @Assert(rsaVerifyStatus, -1)
        @Assert(rsaPubStatus, -1)
    }

    @TestCase
    public func testRsaPubkeyFromPkcs8AcceptsPublicKeyAndLegacyRsaPublicKeyPem(): Unit {
        let spkiPem = (
            "-----BEGIN PUBLIC KEY-----\n" +
            "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAMygHhAucSW8j431vnlCxZKhDM3t+b/R\n" +
            "0fPLNbgfn+8XGp2twf9+7jAHu0e6TjoIgeawwDRDMWLyarpgKpYiPZsCAwEAAQ==\n" +
            "-----END PUBLIC KEY-----\n"
        )
        let pkcs1Pem = (
            "-----BEGIN RSA PUBLIC KEY-----\n" +
            "MEgCQQDMoB4QLnElvI+N9b55QsWSoQzN7fm/0dHzyzW4H5/vFxqdrcH/fu4wB7tH\n" +
            "uk46CIHmsMA0QzFi8mq6YCqWIj2bAgMBAAE=\n" +
            "-----END RSA PUBLIC KEY-----\n"
        )
        let expectedModulus = hexToBytes(
            "CCA01E102E7125BC8F8DF5BE7942C592A10CCDEDF9BFD1D1F3CB35B81F9FEF17" +
            "1A9DADC1FF7EEE3007BB47BA4E3A0881E6B0C034433162F26ABA602A96223D9B"
        )
        let expectedExponent = hexToBytes("010001")

        assertRsaPubkeyFromPem(spkiPem, expectedModulus, expectedExponent)
        assertRsaPubkeyFromPem(pkcs1Pem, expectedModulus, expectedExponent)
    }

    @TestCase
    public func testRsaPubkeyFromPkcs8RejectsNonRsaSpki(): Unit {
        let ecSpkiPem = (
            "-----BEGIN PUBLIC KEY-----\n" +
            "MBkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDAgAA\n" +
            "-----END PUBLIC KEY-----\n"
        )
        let pemBytes = ecSpkiPem.toArray()
        let pemPtr = unsafe { LibC.malloc<UInt8>(count: pemBytes.size) }
        let nOut = unsafe { LibC.malloc<UInt8>(count: 64) }
        let eOut = unsafe { LibC.malloc<UInt8>(count: 8) }
        let nLen = unsafe { LibC.malloc<Int64>(count: 1) }
        let eLen = unsafe { LibC.malloc<Int64>(count: 1) }

        if (
            pemPtr.isNull() ||
            nOut.isNull() ||
            eOut.isNull() ||
            nLen.isNull() ||
            eLen.isNull()
        ) {
            freeIfPresent(pemPtr)
            freeIfPresent(nOut)
            freeIfPresent(eOut)
            freeIfPresent(nLen)
            freeIfPresent(eLen)
            @Fail("RSA public-key FFI test allocation failed")
            return
        }

        try {
            writeBytes(pemBytes, pemPtr)
            unsafe {
                nLen.write(64)
                eLen.write(8)
            }
            let status = unsafe {
                rsa_pubkey_from_pkcs8(
                    pemPtr,
                    pemBytes.size,
                    nOut,
                    nLen,
                    eOut,
                    eLen
                )
            }
            @Assert(status, -3)
        } finally {
            unsafe { LibC.free(eLen) }
            unsafe { LibC.free(nLen) }
            unsafe { LibC.free(eOut) }
            unsafe { LibC.free(nOut) }
            unsafe { LibC.free(pemPtr) }
        }
    }
}

private func assertRsaPubkeyFromPem(
    pem: String,
    expectedModulus: Array<Byte>,
    expectedExponent: Array<Byte>
): Unit {
    let pemBytes = pem.toArray()
    let pemPtr = unsafe { LibC.malloc<UInt8>(count: pemBytes.size) }
    let nOut = unsafe { LibC.malloc<UInt8>(count: expectedModulus.size) }
    let eOut = unsafe { LibC.malloc<UInt8>(count: expectedExponent.size) }
    let nLen = unsafe { LibC.malloc<Int64>(count: 1) }
    let eLen = unsafe { LibC.malloc<Int64>(count: 1) }

    if (
        pemPtr.isNull() ||
        nOut.isNull() ||
        eOut.isNull() ||
        nLen.isNull() ||
        eLen.isNull()
    ) {
        freeIfPresent(pemPtr)
        freeIfPresent(nOut)
        freeIfPresent(eOut)
        freeIfPresent(nLen)
        freeIfPresent(eLen)
        @Fail("RSA public-key FFI test allocation failed")
        return
    }

    try {
        writeBytes(pemBytes, pemPtr)
        unsafe {
            nLen.write(expectedModulus.size)
            eLen.write(expectedExponent.size)
        }

        let status = unsafe {
            rsa_pubkey_from_pkcs8(
                pemPtr,
                pemBytes.size,
                nOut,
                nLen,
                eOut,
                eLen
            )
        }

        @Assert(status, 0)
        @Assert(unsafe { nLen.read() }, expectedModulus.size)
        @Assert(unsafe { eLen.read() }, expectedExponent.size)
        @Assert(readBytes(nOut, expectedModulus.size), expectedModulus)
        @Assert(readBytes(eOut, expectedExponent.size), expectedExponent)
    } finally {
        unsafe { LibC.free(eLen) }
        unsafe { LibC.free(nLen) }
        unsafe { LibC.free(eOut) }
        unsafe { LibC.free(nOut) }
        unsafe { LibC.free(pemPtr) }
    }
}

private func writeBytes(bytes: Array<Byte>, ptr: CPointer<UInt8>): Unit {
    for (i in 0..bytes.size) {
        unsafe { ptr.write(i, UInt8(bytes[i])) }
    }
}

private func readBytes(ptr: CPointer<UInt8>, size: Int64): Array<Byte> {
    let out = Array<Byte>(size, repeat: 0)
    for (i in 0..size) {
        out[i] = unsafe { ptr.read(i) }
    }
    out
}

private func freeIfPresent<T>(ptr: CPointer<T>): Unit where T <: CType {
    if (ptr.isNotNull()) {
        unsafe { LibC.free(ptr) }
    }
}

private func hexToBytes(hex: String): Array<Byte> {
    let clean = hex.trimAscii().replace(" ", "").replace("\n", "").replace("\t", "")
    if ((clean.size % 2) != 0) {
        throw Exception("invalid hex length")
    }
    let out = Array<Byte>(clean.size / 2, repeat: 0)
    var i = 0
    while (i < clean.size) {
        let hi = hexNibble(clean[i])
        let lo = hexNibble(clean[i + 1])
        out[i / 2] = UInt8((hi << 4) | lo)
        i += 2
    }
    out
}

private func hexNibble(ch: Byte): UInt8 {
    if (ch >= b'0' && ch <= b'9') {
        return UInt8(ch - b'0')
    }
    let lower = if (ch >= b'A' && ch <= b'F') {
        ch + 32
    } else {
        ch
    }
    if (lower >= b'a' && lower <= b'f') {
        return UInt8(lower - b'a' + 10)
    }
    throw Exception("invalid hex char")
}
