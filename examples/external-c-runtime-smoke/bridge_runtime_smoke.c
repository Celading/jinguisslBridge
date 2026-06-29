#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

extern void CJ_MRT_CjRuntimeInit(void);
extern void CJ_MRT_SetCommandLineArgs(int argc, char **argv);
extern int CJ_MRT_CjRuntimeStart(int (*entry)(void));

typedef int32_t (*bridge_ffi_init_fn)(uint8_t *version_out, int64_t *version_len);
typedef int32_t (*ed25519_sign_fn)(uint8_t *msg, int64_t msg_len, uint8_t *seed, int64_t seed_len, uint8_t *sig_out, int64_t *sig_out_len);
typedef int32_t (*ed25519_verify_fn)(uint8_t *msg, int64_t msg_len, uint8_t *sig, int64_t sig_len, uint8_t *pubkey, int64_t pubkey_len);
typedef int32_t (*ed25519_pubkey_from_seed_fn)(uint8_t *seed, int64_t seed_len, uint8_t *pub_out, int64_t *pub_out_len);
typedef int32_t (*ecc_p256_sign_fn)(uint8_t *digest, int64_t digest_len, uint8_t *scalar, int64_t scalar_len, uint8_t *r_out, int64_t *r_out_len, uint8_t *s_out, int64_t *s_out_len);
typedef int32_t (*ecc_p256_verify_fn)(uint8_t *digest, int64_t digest_len, uint8_t *pubkey_x, int64_t pubkey_x_len, uint8_t *pubkey_y, int64_t pubkey_y_len, uint8_t *r, int64_t r_len, uint8_t *s, int64_t s_len);
typedef int32_t (*ecc_p256_pubkey_from_scalar_fn)(uint8_t *scalar, int64_t scalar_len, uint8_t *x_out, int64_t *x_out_len, uint8_t *y_out, int64_t *y_out_len);
typedef int32_t (*rsa_sign_sha256_fn)(uint8_t *msg, int64_t msg_len, uint8_t *pem, int64_t pem_len, uint8_t *sig_out, int64_t *sig_out_len);
typedef int32_t (*rsa_verify_sha256_fn)(uint8_t *msg, int64_t msg_len, uint8_t *sig, int64_t sig_len, uint8_t *modulus, int64_t modulus_len, uint8_t *exponent, int64_t exponent_len);
typedef int32_t (*rsa_pubkey_from_pkcs8_fn)(uint8_t *pem, int64_t pem_len, uint8_t *n_out, int64_t *n_out_len, uint8_t *e_out, int64_t *e_out_len);

static const char *g_bridge_path = NULL;

static void *load_symbol(void *handle, const char *name) {
    void *sym = dlsym(handle, name);
    if (sym == NULL) {
        fprintf(stderr, "dlsym %s failed: %s\n", name, dlerror());
    }
    return sym;
}

static const char *default_bridge_path(void) {
    const char *env_path = getenv("JINGUISSL_BRIDGE_DYLIB");
    if (env_path != NULL && env_path[0] != '\0') {
        return env_path;
    }
    return "../../target/release/jinguissl_bridge/libjinguissl_bridge.dylib";
}

static int c_entry(void) {
    const char *bridge_path = g_bridge_path;
    if (bridge_path == NULL || bridge_path[0] == '\0') {
        bridge_path = default_bridge_path();
    }

    void *handle = dlopen(bridge_path, RTLD_NOW | RTLD_GLOBAL);
    if (handle == NULL) {
        fprintf(stderr, "dlopen %s failed: %s\n", bridge_path, dlerror());
        return 10;
    }

    bridge_ffi_init_fn bridge_ffi_init = (bridge_ffi_init_fn)load_symbol(handle, "bridge_ffi_init");
    ed25519_sign_fn ed25519_sign = (ed25519_sign_fn)load_symbol(handle, "ed25519_sign");
    ed25519_verify_fn ed25519_verify = (ed25519_verify_fn)load_symbol(handle, "ed25519_verify");
    ed25519_pubkey_from_seed_fn ed25519_pubkey_from_seed = (ed25519_pubkey_from_seed_fn)load_symbol(handle, "ed25519_pubkey_from_seed");
    ecc_p256_sign_fn ecc_p256_sign = (ecc_p256_sign_fn)load_symbol(handle, "ecc_p256_sign");
    ecc_p256_verify_fn ecc_p256_verify = (ecc_p256_verify_fn)load_symbol(handle, "ecc_p256_verify");
    ecc_p256_pubkey_from_scalar_fn ecc_p256_pubkey_from_scalar = (ecc_p256_pubkey_from_scalar_fn)load_symbol(handle, "ecc_p256_pubkey_from_scalar");
    rsa_sign_sha256_fn rsa_sign_sha256 = (rsa_sign_sha256_fn)load_symbol(handle, "rsa_sign_sha256");
    rsa_verify_sha256_fn rsa_verify_sha256 = (rsa_verify_sha256_fn)load_symbol(handle, "rsa_verify_sha256");
    rsa_pubkey_from_pkcs8_fn rsa_pubkey_from_pkcs8 = (rsa_pubkey_from_pkcs8_fn)load_symbol(handle, "rsa_pubkey_from_pkcs8");
    if (
        bridge_ffi_init == NULL ||
        ed25519_sign == NULL ||
        ed25519_verify == NULL ||
        ed25519_pubkey_from_seed == NULL ||
        ecc_p256_sign == NULL ||
        ecc_p256_verify == NULL ||
        ecc_p256_pubkey_from_scalar == NULL ||
        rsa_sign_sha256 == NULL ||
        rsa_verify_sha256 == NULL ||
        rsa_pubkey_from_pkcs8 == NULL
    ) {
        dlclose(handle);
        return 11;
    }

    int32_t null_status = bridge_ffi_init(NULL, NULL);
    printf("null_status=%d\n", null_status);
    if (null_status != -1) {
        dlclose(handle);
        return 12;
    }

    uint8_t small[1] = {0};
    int64_t small_len = 1;
    int32_t small_status = bridge_ffi_init(small, &small_len);
    printf("small_status=%d small_len=%lld\n", small_status, (long long)small_len);
    if (small_status != -2) {
        dlclose(handle);
        return 13;
    }

    uint8_t version[64] = {0};
    int64_t version_len = 64;
    int32_t ok_status = bridge_ffi_init(version, &version_len);
    printf("ok_status=%d version_len=%lld version=%.*s\n", ok_status, (long long)version_len, (int)version_len, version);
    if (ok_status != 0) {
        dlclose(handle);
        return 14;
    }

    int64_t len = 0;
    int32_t statuses[9];
    statuses[0] = ed25519_sign(NULL, 0, NULL, 0, NULL, &len);
    statuses[1] = ed25519_verify(NULL, 0, NULL, 0, NULL, 0);
    statuses[2] = ed25519_pubkey_from_seed(NULL, 0, NULL, &len);
    statuses[3] = ecc_p256_sign(NULL, 0, NULL, 0, NULL, &len, NULL, &len);
    statuses[4] = ecc_p256_verify(NULL, 0, NULL, 0, NULL, 0, NULL, 0, NULL, 0);
    statuses[5] = ecc_p256_pubkey_from_scalar(NULL, 0, NULL, &len, NULL, &len);
    statuses[6] = rsa_sign_sha256(NULL, 0, NULL, 0, NULL, &len);
    statuses[7] = rsa_verify_sha256(NULL, 0, NULL, 0, NULL, 0, NULL, 0);
    statuses[8] = rsa_pubkey_from_pkcs8(NULL, 0, NULL, &len, NULL, &len);

    const char *names[9] = {
        "ed25519_sign",
        "ed25519_verify",
        "ed25519_pubkey_from_seed",
        "ecc_p256_sign",
        "ecc_p256_verify",
        "ecc_p256_pubkey_from_scalar",
        "rsa_sign_sha256",
        "rsa_verify_sha256",
        "rsa_pubkey_from_pkcs8"
    };
    for (int i = 0; i < 9; i++) {
        printf("%s_null_status=%d\n", names[i], statuses[i]);
        if (statuses[i] != -1) {
            dlclose(handle);
            return 20 + i;
        }
    }

    dlclose(handle);
    return 0;
}

int main(int argc, char **argv) {
    if (argc > 1) {
        g_bridge_path = argv[1];
    }
    CJ_MRT_CjRuntimeInit();
    CJ_MRT_SetCommandLineArgs(argc, argv);
    return CJ_MRT_CjRuntimeStart(c_entry);
}
