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
}
