package jinguissl_bridge

import std.collection.ArrayList
import jinguissl_core.jinguissl.crypto.ed25519.{ed25519Sign, ed25519Verify, ed25519PublicKeyFromSeed}

/**
 * Ed25519 FFI barrier.
 *
 * C-compatible exports for ed25519 sign, verify, and public key derivation.
 * All functions accept caller-provided output buffers.
 *
 * Return codes:
 *   0  = success
 *  -1  = bad input (null pointer, invalid length)
 *  -2  = output buffer too small
 *  -3  = crypto error (verify failed)
 */

@C
public func ed25519_sign(
    msg: CPointer<UInt8>, msgLen: Int64,
    seed: CPointer<UInt8>, seedLen: Int64,
    sigOut: CPointer<UInt8>, sigOutLen: CPointer<Int64>
): Int32 {
    unsafe {
        if (msg.isNull() || seed.isNull() || sigOut.isNull() || sigOutLen.isNull()) { return -1 }
        if (msgLen < 0 || seedLen != 32) { return -1 }
        let msgBytes = ptrToBytes(msg, msgLen)
        let seedBytes = ptrToBytes(seed, seedLen)
        let sig = ed25519Sign(seedBytes, msgBytes)
        if (sig.size > sigOutLen.read()) { return -2 }
        bytesToPtr(sig, sigOut)
        sigOutLen.write(sig.size)
        0
    }
}

@C
public func ed25519_verify(
    msg: CPointer<UInt8>, msgLen: Int64,
    sig: CPointer<UInt8>, sigLen: Int64,
    pubkey: CPointer<UInt8>, pubkeyLen: Int64
): Int32 {
    unsafe {
        if (msg.isNull() || sig.isNull() || pubkey.isNull()) { return -1 }
        if (msgLen < 0 || sigLen != 64 || pubkeyLen != 32) { return -1 }
        let msgBytes = ptrToBytes(msg, msgLen)
        let sigBytes = ptrToBytes(sig, sigLen)
        let pubBytes = ptrToBytes(pubkey, pubkeyLen)
        if (ed25519Verify(pubBytes, msgBytes, sigBytes)) { 0 } else { -3 }
    }
}

@C
public func ed25519_pubkey_from_seed(
    seed: CPointer<UInt8>, seedLen: Int64,
    pubOut: CPointer<UInt8>, pubOutLen: CPointer<Int64>
): Int32 {
    unsafe {
        if (seed.isNull() || pubOut.isNull() || pubOutLen.isNull()) { return -1 }
        if (seedLen != 32) { return -1 }
        let seedBytes = ptrToBytes(seed, seedLen)
        let pubkey = ed25519PublicKeyFromSeed(seedBytes)
        if (pubkey.size > pubOutLen.read()) { return -2 }
        bytesToPtr(pubkey, pubOut)
        pubOutLen.write(pubkey.size)
        0
    }
}

/**
 * Call this function from C to force linking of all FFI symbols.
 * Returns the bridge version string.
 * C signature: `extern int32_t bridge_ffi_init(int32_t* version_len);`
 */
@C
public func bridge_ffi_init(versionOut: CPointer<UInt8>, versionOutLen: CPointer<Int64>): Int32 {
    unsafe {
        let version = "jinguissl-bridge-ffi-0.1.0"
        let runes = version.toRuneArray()
        let bytes = ArrayList<Byte>()
        for (ch in runes) { bytes.add(UInt8(UInt32(ch))) }
        let bArr = bytes.toArray()
        if (bArr.size > versionOutLen.read()) { return -2 }
        bytesToPtr(bArr, versionOut)
        versionOutLen.write(bArr.size)
        0
    }
}

// ---------------------------------------------------------------------------
// CPointer <-> Array<Byte>
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
