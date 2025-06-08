#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <oqs/oqs.h>

// Print up to max_print bytes of a buffer as hex
void hex_print(const char *label, const uint8_t *buf, size_t len, size_t max_print) {
    printf("%s (len=%zu): ", label, len);
    size_t n = len < max_print ? len : max_print;
    for (size_t i = 0; i < n; i++) printf("%02x", buf[i]);
    if (n < len) printf("...");
    printf("\n");
}

// Pause and wait for user input
void pause(const char *msg) {
    printf("%s\n", msg ? msg : "Press Enter to continue...");
    getchar();
}

// Print all named fields from Dilithium2 secret key
void print_sk_fields(const uint8_t *sk) {
    printf("  [Extracted fields from secret key (ML-DSA-44)]:\n");
    size_t off = 0;
    hex_print("    rho", sk + off, 32, 32);     off += 32;
    hex_print("    K",   sk + off, 32, 32);     off += 32;
    hex_print("    tr",  sk + off, 48, 32);     off += 48;
    hex_print("    s1",  sk + off, 640, 32);    off += 640;
    hex_print("    s2",  sk + off, 352, 32);    off += 352;
    hex_print("    t0",  sk + off, 896, 32);    off += 896;
}

void print_pk_fields(const uint8_t *pk) {
    printf("  [Extracted fields from public key ML-DSA-44(Dilithium2)]:\n");
    hex_print("    rho", pk, 32, 32);
    hex_print("    t1",  pk+32, 1280, 32);
}

int main() {
    const char *alg = OQS_SIG_alg_dilithium_2;

    printf("=====================================================================\n");
    printf("[Initialization] ML-DSA-44 (Dilithium2) FIPS 204 Demo using liboqs C API\n");
    printf("=====================================================================\n");

    // Step 0: Instantiate
    printf("\n[Step 0] Instantiate signature object for algorithm (ML-DSA-44): %s\n", alg);
    OQS_SIG *sig = OQS_SIG_new(alg);
    if (!sig) {
        printf("ERROR: Algorithm %s not enabled in liboqs!\n", alg);
        return EXIT_FAILURE;
    }
    printf("[Step 0] Algorithm details:\n");
    printf("  - Public key length : %zu bytes\n", sig->length_public_key);
    printf("  - Secret key length : %zu bytes\n", sig->length_secret_key);
    printf("  - Signature length  : %zu bytes\n", sig->length_signature);
    printf("----------------------------------------------------------------------\n");
    pause("Press Enter to continue to Key Generation...");

    // --------------------------------------
    // Key Generation (Pseudocode/Conceptual)
    // --------------------------------------
    printf("[KeyGen] --- ML-DSA.KeyGen (Algorithm 1 & 6, FIPS 204) ---\n");

    printf("\nStep 1: Generate random master seed zeta\n");
    printf("    Formula: zeta <- randombytes(32)\n");
    printf("    [liboqs internal: not directly accessible]\n");
    pause(NULL);

    printf("Step 2: Expand zeta to get rho, K\n");
    printf("    Formula: (rho, K) = ExpandSeed(zeta)\n");
    printf("    [rho is the seed for public matrix A]\n");
    printf("    [liboqs internal: not directly accessible]\n");
    pause(NULL);

    printf("Step 3: Expand rho to get public matrix A\n");
    printf("    Formula: A = ExpandMatrix(rho)\n");
    printf("    [liboqs internal: not directly accessible]\n");
    pause(NULL);

    printf("Step 4: Sample secret vectors s1, s2\n");
    printf("    Formula: (s1, s2) <- SampleShortVectors(seed)\n");
    printf("    [liboqs internal: not directly accessible]\n");
    pause(NULL);

    printf("Step 5: Compute t = A.s1 + s2\n");
    printf("    Formula: t = A.s_1 + s_2\n");
    printf("    [liboqs internal: not directly accessible]\n");
    pause(NULL);

    printf("Step 6: Compress t to t1, t0\n");
    printf("    Formula: (t1, t0) = Compress(t)\n");
    printf("    [liboqs internal: not directly accessible]\n");
    pause(NULL);

    printf("Step 7: Form public and secret keys\n");
    printf("    Public key:  pk = (rho, t1)\n");
    printf("    Secret key:  sk = (rho, K, tr, s1, s2, t0)\n");
    printf("    where tr = H(pk)\n");
    pause("Press Enter to call OQS_SIG_keypair() and extract/print real key values...");

    uint8_t *public_key = malloc(sig->length_public_key);
    uint8_t *secret_key = malloc(sig->length_secret_key);
    if (OQS_SIG_keypair(sig, public_key, secret_key) != OQS_SUCCESS) {
        printf("ERROR: Key generation failed!\n");
        return EXIT_FAILURE;
    }
    printf("\n[KeyGen] Extracted Key Components:\n");
    print_pk_fields(public_key);
    print_sk_fields(secret_key);
    pause("Press Enter to continue to Signing...");

    // --------------------------------------
    // Signing (Pseudocode/Conceptual)
    // --------------------------------------
    printf("[Sign] --- ML-DSA.Sign (Algorithm 2 & 7, FIPS 204) ---\n");
    const char *message = "This is the message to be signed for the demo.";
    size_t msg_len = strlen(message);

    printf("\nStep 1: Set message M to be signed.\n");
    printf("    M = \"%s\"\n", message);
    pause(NULL);

    printf("Step 2: Compute tr = H(pk)\n");
    printf("    Formula: tr = H(pk)\n");
    printf("    [tr is stored as part of the secret key]\n");
    pause(NULL);

    printf("Step 3: Generate random coins r for signing\n");
    printf("    Formula: r <- randombytes(32)\n");
    printf("    [liboqs internal: not directly accessible]\n");
    pause(NULL);

    printf("Step 4: Compute message representative mu\n");
    printf("    Formula: mu = H(tr || M || r)\n");
    printf("    [liboqs internal: not directly accessible]\n");
    pause(NULL);

    printf("Step 5: Rejection sampling for signature components:\n");
    printf("    Loop:\n");
    printf("      y <- SampleShortVector(random)\n");
    printf("      w = A.y\n");
    printf("      c_tilde = H(mu || w)\n");
    printf("      c = Decode(c_tilde)\n");
    printf("      z = y + c.s1\n");
    printf("      if ||z||_∞ >= B, reject\n");
    printf("      h = MakeHint(w - c.t1, ...)\n");
    printf("      if h invalid, reject\n");
    printf("    Output signature: sigma = (c_tilde, z, h)\n");
    pause("Press Enter to call OQS_SIG_sign() and view real signature value...");

    uint8_t *signature = malloc(sig->length_signature);
    size_t sig_len = 0;
    if (OQS_SIG_sign(sig, signature, &sig_len, (const uint8_t *)message, msg_len, secret_key) != OQS_SUCCESS) {
        printf("ERROR: Signing failed!\n");
        return EXIT_FAILURE;
    }
    hex_print("[Sign] Signature (sigma = c_tilde || z || h)", signature, sig_len, 32);
    pause("Press Enter to continue to Verification...");

    // --------------------------------------
    // Verification (Pseudocode/Conceptual)
    // --------------------------------------
    printf("[Verify] --- ML-DSA.Verify (Algorithm 3 & 8, FIPS 204) ---\n");

    printf("\nStep 1: Input message M, pk, sigma\n");
    printf("    M = \"%s\"\n", message);
    pause(NULL);

    printf("Step 2: Parse pk into rho, t1\n");
    printf("    pk = (rho, t1)\n");
    pause(NULL);

    printf("Step 3: Parse sigma into c_tilde, z, h\n");
    printf("    sigma = (c_tilde, z, h)\n");
    pause(NULL);

    printf("Step 4: Check bounds on z\n");
    printf("    Accept only if ||z||_inf < B\n");
    pause(NULL);

    printf("Step 5: Expand rho to get public matrix A\n");
    printf("    A = ExpandMatrix(rho)\n");
    pause(NULL);

    printf("Step 6: Compute message representative mu\n");
    printf("    mu = H(H(pk) || M)\n");
    pause(NULL);

    printf("Step 7: Decode c_tilde to challenge c\n");
    printf("    c = Decode(c_tilde)\n");
    pause(NULL);

    printf("Step 8: Compute w1' = UseHint(h, A.z - c.t1)\n");
    printf("    w1' = UseHint(h, A.z - c.t1)\n");
    pause(NULL);

    printf("Step 9: Accept if c_tilde == H(mu || w1'), else reject\n");
    pause("Press Enter to call OQS_SIG_verify()...");

    OQS_STATUS result = OQS_SIG_verify(sig, (const uint8_t *)message, msg_len, signature, sig_len, public_key);
    if (result == OQS_SUCCESS) {
        printf("[Verify] Signature is VALID [OK]\n");
    } else {
        printf("[Verify] Signature is INVALID [X]\n");
    }
    pause("Press Enter to try tampered message...");

    const char *tampered_msg = "This is NOT the message that was signed.";
    printf("[Verify] --- Tampered Message Verification Demo ---\n");
    printf("    M (tampered) = \"%s\"\n", tampered_msg);
    OQS_STATUS tampered_result = OQS_SIG_verify(sig, (const uint8_t *)tampered_msg, strlen(tampered_msg), signature, sig_len, public_key);
    if (tampered_result != OQS_SUCCESS) {
        printf("[Verify] Tampered message verification FAILED [X]\n");
    } else {
        printf("[Verify] ERROR: Tampered message verification PASSED [X]\n");
    }
    printf("----------------------------------------------------------------------\n");

    // Cleanup
    free(public_key);
    free(secret_key);
    free(signature);
    OQS_SIG_free(sig);

    printf("[Demo Complete]\n");
    pause("Press Enter to exit.");
    return EXIT_SUCCESS;
}
