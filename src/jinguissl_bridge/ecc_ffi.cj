package jinguissl_bridge

import std.collection.ArrayList
import jinguissl_core.crypto.bignum.BigNum
import jinguissl_core.crypto.ecc.*

/**
 * ECC (P-256) FFI barrier.
 *
 * Sign/verify produce/consume (r, s) as two fixed-size 32-byte big-endian buffers.
 *
 * Return codes:
 *   0  = success
 *  -1  = bad input
 *  -2  = output buffer too small
 *  -3  = crypto error (verify failed)
 */

@C
public func ecc_p256_sign(
    digest: CPointer<UInt8>, digestLen: Int64,
    scalar: CPointer<UInt8>, scalarLen: Int64,
    rOut: CPointer<UInt8>, rOutLen: CPointer<Int64>,
    sOut: CPointer<UInt8>, sOutLen: CPointer<Int64>
): Int32 {
    unsafe {
        if (digest.isNull() || scalar.isNull() || rOut.isNull() || rOutLen.isNull() || sOut.isNull() || sOutLen.isNull()) {
            return -1
        }
        if (digestLen != 32 || scalarLen != 32) { return -1 }
        let digestBytes = ptrToBytes(digest, digestLen)
        let scalarBytes = ptrToBytes(scalar, scalarLen)
        let scalarBn = BigNum.fromBytesBE(scalarBytes)
        let privKey = EcPrivateKey(NamedCurve.P256, scalarBn)
        let (r, s) = ecdsaSign(privKey, digestBytes)
        let rBE = r.toBytesBE(paddedLen: 32)
        let sBE = s.toBytesBE(paddedLen: 32)
        let rLen = rOutLen.read()
        let sLen = sOutLen.read()
        if (rBE.size > rLen || sBE.size > sLen) { return -2 }
        bytesToPtr(rBE, rOut)
        rOutLen.write(rBE.size)
        bytesToPtr(sBE, sOut)
        sOutLen.write(sBE.size)
        0
    }
}

@C
public func ecc_p256_verify(
    digest: CPointer<UInt8>, digestLen: Int64,
    pubkeyX: CPointer<UInt8>, pubkeyXLen: Int64,
    pubkeyY: CPointer<UInt8>, pubkeyYLen: Int64,
    r: CPointer<UInt8>, rLen: Int64,
    s: CPointer<UInt8>, sLen: Int64
): Int32 {
    unsafe {
        if (digest.isNull() || pubkeyX.isNull() || pubkeyY.isNull() || r.isNull() || s.isNull()) { return -1 }
        if (digestLen != 32 || pubkeyXLen != 32 || pubkeyYLen != 32 || rLen != 32 || sLen != 32) { return -1 }
        let digestBytes = ptrToBytes(digest, digestLen)
        let x = BigNum.fromBytesBE(ptrToBytes(pubkeyX, pubkeyXLen))
        let y = BigNum.fromBytesBE(ptrToBytes(pubkeyY, pubkeyYLen))
        let rBn = BigNum.fromBytesBE(ptrToBytes(r, rLen))
        let sBn = BigNum.fromBytesBE(ptrToBytes(s, sLen))
        let pubKey = EcPublicKey(NamedCurve.P256, x, y)
        if (ecdsaVerify(pubKey, digestBytes, rBn, sBn)) { 0 } else { -3 }
    }
}

@C
public func ecc_p256_pubkey_from_scalar(
    scalar: CPointer<UInt8>, scalarLen: Int64,
    xOut: CPointer<UInt8>, xOutLen: CPointer<Int64>,
    yOut: CPointer<UInt8>, yOutLen: CPointer<Int64>
): Int32 {
    unsafe {
        if (scalar.isNull() || xOut.isNull() || xOutLen.isNull() || yOut.isNull() || yOutLen.isNull()) { return -1 }
        if (scalarLen != 32) { return -1 }
        let scalarBytes = ptrToBytes(scalar, scalarLen)
        let scalarBn = BigNum.fromBytesBE(scalarBytes)
        let privKey = EcPrivateKey(NamedCurve.P256, scalarBn)
        let pubKey = ecPublicFromPrivateKey(privKey)
        let xBytes = pubKey.x.toBytesBE(paddedLen: 32)
        let yBytes = pubKey.y.toBytesBE(paddedLen: 32)
        let xLen = xOutLen.read()
        let yLen = yOutLen.read()
        if (xBytes.size > xLen || yBytes.size > yLen) { return -2 }
        bytesToPtr(xBytes, xOut)
        xOutLen.write(xBytes.size)
        bytesToPtr(yBytes, yOut)
        yOutLen.write(yBytes.size)
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
