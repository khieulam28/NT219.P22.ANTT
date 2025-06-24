#include <stdio.h>
#include <string.h>
#include <oqs/oqs.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>

void handle_openssl_errors() {
    ERR_print_errors_fp(stderr);
    abort();
}

RSA* generate_rsa_key() {
    RSA *rsa = RSA_new();
    BIGNUM *e = BN_new();
    BN_set_word(e, RSA_F4);
    RSA_generate_key_ex(rsa, 2048, e, NULL);
    BN_free(e);
    return rsa;
}

int main() {
    // ======= 1. TẠO KHÓA RSA =======
    RSA *rsa = generate_rsa_key();
    if (!rsa) handle_openssl_errors();

    // ======= 2. TẠO KHÓA DILITHIUM2 =======
    const char *alg_name = OQS_SIG_alg_dilithium_2;
    OQS_SIG *sig = OQS_SIG_new(alg_name);
    if (sig == NULL) {
        printf("Không hỗ trợ Dilithium-2!\n");
        return 1;
    }

    uint8_t *pub_key = malloc(sig->length_public_key);
    uint8_t *priv_key = malloc(sig->length_secret_key);
    OQS_SIG_keypair(sig, pub_key, priv_key);

    // ======= 3. THÔNG ĐIỆP =======
    const char *message = "Hello from RSA + Dilithium-2!";
    size_t msg_len = strlen(message);

    // ======= 4. KÝ BẰNG DILITHIUM2 =======
    uint8_t *signature = malloc(sig->length_signature);
    size_t sig_len;
    OQS_SIG_sign(sig, signature, &sig_len, (const uint8_t *)message, msg_len, priv_key);

    // ======= 5. XÁC MINH =======
    if (OQS_SIG_verify(sig, (const uint8_t *)message, msg_len, signature, sig_len, pub_key) == OQS_SUCCESS) {
        printf(" Xác minh Dilithium-2: THÀNH CÔNG\n");
    } else {
        printf(" Xác minh thất bại!\n");
    }

    // ======= 6. MÃ HÓA BẰNG RSA =======
    unsigned char encrypted[256];
    int enc_len = RSA_public_encrypt(msg_len, (unsigned char *)message, encrypted, rsa, RSA_PKCS1_OAEP_PADDING);
    if (enc_len == -1) handle_openssl_errors();
    printf(" Đã mã hóa bằng RSA\n");

    // ======= 7. GIẢI MÃ BẰNG RSA =======
    unsigned char decrypted[256];
    int dec_len = RSA_private_decrypt(enc_len, encrypted, decrypted, rsa, RSA_PKCS1_OAEP_PADDING);
    if (dec_len == -1) handle_openssl_errors();
    decrypted[dec_len] = '\0';
    printf(" Đã giải mã bằng RSA: %s\n", decrypted);

    // ======= GIẢI PHÓNG BỘ NHỚ =======
    OQS_SIG_free(sig);
    free(pub_key);
    free(priv_key);
    free(signature);
    RSA_free(rsa);

    return 0;
}