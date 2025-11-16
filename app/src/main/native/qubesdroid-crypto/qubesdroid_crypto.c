/*
 * QubesDroid JNI Bridge - Post-Quantum Crypto Operations
 *
 * This JNI bridge exposes ChaCha20-Poly1305 and Kyber-1024 operations
 * to the Android Java layer.
 */

#include <jni.h>
#include <string.h>
#include <stdlib.h>
#include <android/log.h>

// Include crypto headers (use include paths from Android.mk)
#include "chacha20poly1305.h"
#include "poly1305.h"
#include "chacha256.h"
#include "argon2.h"
#include "mlkem1024.h"

#define LOG_TAG "QubesDroid-Crypto"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

/*
 * Class:     com_qubesdroid_CryptoNative
 * Method:    deriveKeyFromPassword
 * Signature: (Ljava/lang/String;[B)[B
 *
 * Derive encryption key from password using Argon2id
 * Returns 32-byte key suitable for ChaCha20
 */
JNIEXPORT jbyteArray JNICALL
Java_com_qubesdroid_CryptoNative_deriveKeyFromPassword(
    JNIEnv *env,
    jobject thiz,
    jstring password,
    jbyteArray salt)
{
    const char *pwd = (*env)->GetStringUTFChars(env, password, NULL);
    jbyte *salt_bytes = (*env)->GetByteArrayElements(env, salt, NULL);
    jsize salt_len = (*env)->GetArrayLength(env, salt);

    if (salt_len != 16) {
        LOGE("Invalid salt length: %d (expected 16)", salt_len);
        (*env)->ReleaseStringUTFChars(env, password, pwd);
        (*env)->ReleaseByteArrayElements(env, salt, salt_bytes, JNI_ABORT);
        return NULL;
    }

    // Allocate output key
    uint8_t key[32];

    // Argon2id parameters (mobile-friendly)
    uint32_t t_cost = 4;        // 4 iterations
    uint32_t m_cost = 262144;   // 256 MB memory
    uint32_t parallelism = 4;   // 4 threads

    LOGD("Deriving key with Argon2id (256MB, 4 iterations)");

    int result = argon2id_hash_raw(
        t_cost,
        m_cost,
        parallelism,
        pwd,
        strlen(pwd),
        salt_bytes,
        salt_len,
        key,
        sizeof(key),
        NULL  // pAbortKeyDerivation - not using abort functionality
    );

    // Clear password from memory
    memset((void*)pwd, 0, strlen(pwd));
    (*env)->ReleaseStringUTFChars(env, password, pwd);
    (*env)->ReleaseByteArrayElements(env, salt, salt_bytes, JNI_ABORT);

    if (result != ARGON2_OK) {
        LOGE("Argon2id key derivation failed: %d", result);
        memset(key, 0, sizeof(key));
        return NULL;
    }

    // Convert to Java byte array
    jbyteArray java_key = (*env)->NewByteArray(env, sizeof(key));
    (*env)->SetByteArrayRegion(env, java_key, 0, sizeof(key), (jbyte*)key);

    // Clear sensitive data
    memset(key, 0, sizeof(key));

    LOGI("Key derived successfully");
    return java_key;
}

/*
 * Class:     com_qubesdroid_CryptoNative
 * Method:    encryptData
 * Signature: ([B[B[B[B)[B
 *
 * Encrypt data using ChaCha20-Poly1305
 * Returns ciphertext with 16-byte tag appended
 */
JNIEXPORT jbyteArray JNICALL
Java_com_qubesdroid_CryptoNative_encryptData(
    JNIEnv *env,
    jobject thiz,
    jbyteArray plaintext,
    jbyteArray key,
    jbyteArray nonce,
    jbyteArray aad)
{
    jsize pt_len = (*env)->GetArrayLength(env, plaintext);
    jbyte *pt_bytes = (*env)->GetByteArrayElements(env, plaintext, NULL);
    jbyte *key_bytes = (*env)->GetByteArrayElements(env, key, NULL);
    jbyte *nonce_bytes = (*env)->GetByteArrayElements(env, nonce, NULL);

    jbyte *aad_bytes = NULL;
    jsize aad_len = 0;
    if (aad != NULL) {
        aad_len = (*env)->GetArrayLength(env, aad);
        aad_bytes = (*env)->GetByteArrayElements(env, aad, NULL);
    }

    // Initialize output to NULL (will be set on success)
    jbyteArray output = NULL;

    // Validate inputs
    if ((*env)->GetArrayLength(env, key) != 32) {
        LOGE("Invalid key length");
        goto cleanup;
    }
    if ((*env)->GetArrayLength(env, nonce) != 12) {
        LOGE("Invalid nonce length");
        goto cleanup;
    }

    // Allocate ciphertext and tag
    uint8_t *ciphertext = malloc(pt_len);
    uint8_t tag[16];

    // Encrypt
    int result = chacha20poly1305_encrypt(
        ciphertext,
        tag,
        (uint8_t*)pt_bytes,
        pt_len,
        (uint8_t*)aad_bytes,
        aad_len,
        (uint8_t*)key_bytes,
        (uint8_t*)nonce_bytes
    );

    if (result != 0) {
        LOGE("Encryption failed");
        free(ciphertext);
        goto cleanup;
    }

    // Create output: ciphertext || tag
    output = (*env)->NewByteArray(env, pt_len + 16);
    (*env)->SetByteArrayRegion(env, output, 0, pt_len, (jbyte*)ciphertext);
    (*env)->SetByteArrayRegion(env, output, pt_len, 16, (jbyte*)tag);

    // Cleanup
    memset(ciphertext, 0, pt_len);
    free(ciphertext);
    memset(tag, 0, sizeof(tag));

cleanup:
    (*env)->ReleaseByteArrayElements(env, plaintext, pt_bytes, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, key, key_bytes, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, nonce, nonce_bytes, JNI_ABORT);
    if (aad_bytes != NULL) {
        (*env)->ReleaseByteArrayElements(env, aad, aad_bytes, JNI_ABORT);
    }

    return output;
}

/*
 * Class:     com_qubesdroid_CryptoNative
 * Method:    decryptData
 * Signature: ([B[B[B[B)[B
 *
 * Decrypt data using ChaCha20-Poly1305
 * Input: ciphertext with 16-byte tag appended
 * Returns plaintext or NULL on authentication failure
 */
JNIEXPORT jbyteArray JNICALL
Java_com_qubesdroid_CryptoNative_decryptData(
    JNIEnv *env,
    jobject thiz,
    jbyteArray ciphertext_with_tag,
    jbyteArray key,
    jbyteArray nonce,
    jbyteArray aad)
{
    jsize ct_total_len = (*env)->GetArrayLength(env, ciphertext_with_tag);
    if (ct_total_len < 16) {
        LOGE("Ciphertext too short");
        return NULL;
    }

    jsize ct_len = ct_total_len - 16;
    jbyte *ct_bytes = (*env)->GetByteArrayElements(env, ciphertext_with_tag, NULL);
    jbyte *key_bytes = (*env)->GetByteArrayElements(env, key, NULL);
    jbyte *nonce_bytes = (*env)->GetByteArrayElements(env, nonce, NULL);

    jbyte *aad_bytes = NULL;
    jsize aad_len = 0;
    if (aad != NULL) {
        aad_len = (*env)->GetArrayLength(env, aad);
        aad_bytes = (*env)->GetByteArrayElements(env, aad, NULL);
    }

    // Split ciphertext and tag
    uint8_t *ciphertext = (uint8_t*)ct_bytes;
    uint8_t *tag = (uint8_t*)ct_bytes + ct_len;

    // Allocate plaintext
    uint8_t *plaintext = malloc(ct_len);

    // Decrypt
    int result = chacha20poly1305_decrypt(
        plaintext,
        ciphertext,
        ct_len,
        tag,
        (uint8_t*)aad_bytes,
        aad_len,
        (uint8_t*)key_bytes,
        (uint8_t*)nonce_bytes
    );

    jbyteArray output = NULL;

    if (result != 0) {
        LOGE("Decryption failed - authentication tag mismatch");
        memset(plaintext, 0, ct_len);
    } else {
        // Success - create output
        output = (*env)->NewByteArray(env, ct_len);
        (*env)->SetByteArrayRegion(env, output, 0, ct_len, (jbyte*)plaintext);
        memset(plaintext, 0, ct_len);
        LOGI("Decryption successful");
    }

    free(plaintext);

    // Cleanup
    (*env)->ReleaseByteArrayElements(env, ciphertext_with_tag, ct_bytes, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, key, key_bytes, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, nonce, nonce_bytes, JNI_ABORT);
    if (aad_bytes != NULL) {
        (*env)->ReleaseByteArrayElements(env, aad, aad_bytes, JNI_ABORT);
    }

    return output;
}

/*
 * Class:     com_qubesdroid_CryptoNative
 * Method:    getVersionInfo
 * Signature: ()Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL
Java_com_qubesdroid_CryptoNative_getVersionInfo(JNIEnv *env, jobject thiz)
{
    const char *version = "QubesDroid v1.0.0-alpha\n"
                         "Post-Quantum Cryptography:\n"
                         "  - ChaCha20-Poly1305 (RFC 8439)\n"
                         "  - Kyber-1024 (NIST PQC)\n"
                         "  - Argon2id (RFC 9106)";
    return (*env)->NewStringUTF(env, version);
}

/*
 * =====================================================================
 * ML-KEM-1024 (Kyber-1024) Post-Quantum Key Encapsulation
 * =====================================================================
 */

/*
 * Class:     com_qubesdroid_CryptoNative
 * Method:    mlkemKeypair
 * Signature: ()[Ljava/lang/Object;
 *
 * Generate ML-KEM-1024 keypair
 * Returns Object[] {publicKey, secretKey}
 */
JNIEXPORT jobjectArray JNICALL
Java_com_qubesdroid_CryptoNative_mlkemKeypair(
    JNIEnv *env,
    jobject thiz)
{
    uint8_t pk[MLKEM1024_PUBLICKEYBYTES];
    uint8_t sk[MLKEM1024_SECRETKEYBYTES];

    LOGD("Generating ML-KEM-1024 keypair");

    int result = mlkem1024_keypair(pk, sk);

    if (result != 0) {
        LOGE("ML-KEM-1024 keypair generation failed: %d", result);
        return NULL;
    }

    // Create Java byte arrays
    jbyteArray java_pk = (*env)->NewByteArray(env, MLKEM1024_PUBLICKEYBYTES);
    jbyteArray java_sk = (*env)->NewByteArray(env, MLKEM1024_SECRETKEYBYTES);

    (*env)->SetByteArrayRegion(env, java_pk, 0, MLKEM1024_PUBLICKEYBYTES, (jbyte*)pk);
    (*env)->SetByteArrayRegion(env, java_sk, 0, MLKEM1024_SECRETKEYBYTES, (jbyte*)sk);

    // Clear sensitive data
    memset(pk, 0, sizeof(pk));
    memset(sk, 0, sizeof(sk));

    // Return as Object array
    jobjectArray result_array = (*env)->NewObjectArray(env, 2,
        (*env)->FindClass(env, "[B"), NULL);
    (*env)->SetObjectArrayElement(env, result_array, 0, java_pk);
    (*env)->SetObjectArrayElement(env, result_array, 1, java_sk);

    LOGI("ML-KEM-1024 keypair generated successfully");
    return result_array;
}

/*
 * Class:     com_qubesdroid_CryptoNative
 * Method:    mlkemEncapsulate
 * Signature: ([B)[Ljava/lang/Object;
 *
 * ML-KEM-1024 Encapsulation
 * Returns Object[] {ciphertext, sharedSecret}
 */
JNIEXPORT jobjectArray JNICALL
Java_com_qubesdroid_CryptoNative_mlkemEncapsulate(
    JNIEnv *env,
    jobject thiz,
    jbyteArray publicKey)
{
    jbyte *pk_bytes = (*env)->GetByteArrayElements(env, publicKey, NULL);
    jsize pk_len = (*env)->GetArrayLength(env, publicKey);

    if (pk_len != MLKEM1024_PUBLICKEYBYTES) {
        LOGE("Invalid public key length: %d (expected %d)", pk_len, MLKEM1024_PUBLICKEYBYTES);
        (*env)->ReleaseByteArrayElements(env, publicKey, pk_bytes, JNI_ABORT);
        return NULL;
    }

    uint8_t ct[MLKEM1024_CIPHERTEXTBYTES];
    uint8_t ss[MLKEM1024_BYTES];

    LOGD("ML-KEM-1024 encapsulation");

    int result = mlkem1024_enc(ct, ss, (uint8_t*)pk_bytes);

    (*env)->ReleaseByteArrayElements(env, publicKey, pk_bytes, JNI_ABORT);

    if (result != 0) {
        LOGE("ML-KEM-1024 encapsulation failed: %d", result);
        memset(ct, 0, sizeof(ct));
        memset(ss, 0, sizeof(ss));
        return NULL;
    }

    // Create Java byte arrays
    jbyteArray java_ct = (*env)->NewByteArray(env, MLKEM1024_CIPHERTEXTBYTES);
    jbyteArray java_ss = (*env)->NewByteArray(env, MLKEM1024_BYTES);

    (*env)->SetByteArrayRegion(env, java_ct, 0, MLKEM1024_CIPHERTEXTBYTES, (jbyte*)ct);
    (*env)->SetByteArrayRegion(env, java_ss, 0, MLKEM1024_BYTES, (jbyte*)ss);

    // Clear sensitive data
    memset(ct, 0, sizeof(ct));
    memset(ss, 0, sizeof(ss));

    // Return as Object array
    jobjectArray result_array = (*env)->NewObjectArray(env, 2,
        (*env)->FindClass(env, "[B"), NULL);
    (*env)->SetObjectArrayElement(env, result_array, 0, java_ct);
    (*env)->SetObjectArrayElement(env, result_array, 1, java_ss);

    LOGI("ML-KEM-1024 encapsulation successful");
    return result_array;
}

/*
 * Class:     com_qubesdroid_CryptoNative
 * Method:    mlkemDecapsulate
 * Signature: ([B[B)[B
 *
 * ML-KEM-1024 Decapsulation
 * Returns shared secret
 */
JNIEXPORT jbyteArray JNICALL
Java_com_qubesdroid_CryptoNative_mlkemDecapsulate(
    JNIEnv *env,
    jobject thiz,
    jbyteArray ciphertext,
    jbyteArray secretKey)
{
    jbyte *ct_bytes = (*env)->GetByteArrayElements(env, ciphertext, NULL);
    jbyte *sk_bytes = (*env)->GetByteArrayElements(env, secretKey, NULL);

    jsize ct_len = (*env)->GetArrayLength(env, ciphertext);
    jsize sk_len = (*env)->GetArrayLength(env, secretKey);

    if (ct_len != MLKEM1024_CIPHERTEXTBYTES) {
        LOGE("Invalid ciphertext length: %d (expected %d)", ct_len, MLKEM1024_CIPHERTEXTBYTES);
        (*env)->ReleaseByteArrayElements(env, ciphertext, ct_bytes, JNI_ABORT);
        (*env)->ReleaseByteArrayElements(env, secretKey, sk_bytes, JNI_ABORT);
        return NULL;
    }

    if (sk_len != MLKEM1024_SECRETKEYBYTES) {
        LOGE("Invalid secret key length: %d (expected %d)", sk_len, MLKEM1024_SECRETKEYBYTES);
        (*env)->ReleaseByteArrayElements(env, ciphertext, ct_bytes, JNI_ABORT);
        (*env)->ReleaseByteArrayElements(env, secretKey, sk_bytes, JNI_ABORT);
        return NULL;
    }

    uint8_t ss[MLKEM1024_BYTES];

    LOGD("ML-KEM-1024 decapsulation");

    int result = mlkem1024_dec(ss, (uint8_t*)ct_bytes, (uint8_t*)sk_bytes);

    (*env)->ReleaseByteArrayElements(env, ciphertext, ct_bytes, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, secretKey, sk_bytes, JNI_ABORT);

    if (result != 0) {
        LOGE("ML-KEM-1024 decapsulation failed: %d", result);
        memset(ss, 0, sizeof(ss));
        return NULL;
    }

    // Create Java byte array
    jbyteArray java_ss = (*env)->NewByteArray(env, MLKEM1024_BYTES);
    (*env)->SetByteArrayRegion(env, java_ss, 0, MLKEM1024_BYTES, (jbyte*)ss);

    // Clear sensitive data
    memset(ss, 0, sizeof(ss));

    LOGI("ML-KEM-1024 decapsulation successful");
    return java_ss;
}
