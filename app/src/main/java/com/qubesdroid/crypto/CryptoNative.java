package com.qubesdroid;

/**
 * JNI wrapper for QubesDroid post-quantum cryptography operations
 *
 * Provides access to:
 * - ChaCha20-Poly1305 AEAD encryption
 * - Argon2id key derivation
 * - Kyber-1024 post-quantum KEM (future)
 */
public class CryptoNative {

    static {
        System.loadLibrary("qubesdroid-crypto");
    }

    /**
     * Derive encryption key from password using Argon2id
     *
     * @param password User password
     * @param salt 16-byte random salt
     * @return 32-byte encryption key for ChaCha20-Poly1305
     */
    public native byte[] deriveKeyFromPassword(String password, byte[] salt);

    /**
     * Encrypt data using ChaCha20-Poly1305 AEAD
     *
     * @param plaintext Data to encrypt
     * @param key 32-byte encryption key (from Kyber or deriveKeyFromPassword)
     * @param nonce 12-byte random nonce (must be unique per encryption)
     * @param aad Additional authenticated data (can be null)
     * @return Ciphertext with 16-byte authentication tag appended
     */
    public native byte[] encryptData(byte[] plaintext, byte[] key, byte[] nonce, byte[] aad);

    /**
     * Decrypt data using ChaCha20-Poly1305 AEAD
     *
     * @param ciphertextWithTag Ciphertext with 16-byte tag appended
     * @param key 32-byte encryption key (must match encryption)
     * @param nonce 12-byte nonce (must match encryption)
     * @param aad Additional authenticated data (must match encryption, can be null)
     * @return Decrypted plaintext, or null if authentication fails
     */
    public native byte[] decryptData(byte[] ciphertextWithTag, byte[] key, byte[] nonce, byte[] aad);

    /**
     * Get version and crypto information
     *
     * @return Version string with enabled crypto algorithms
     */
    public native String getVersionInfo();

    /**
     * Generate random salt for Argon2id
     *
     * @return 16-byte random salt
     */
    public static byte[] generateSalt() {
        java.security.SecureRandom random = new java.security.SecureRandom();
        byte[] salt = new byte[16];
        random.nextBytes(salt);
        return salt;
    }

    /**
     * Generate random nonce for ChaCha20-Poly1305
     *
     * @return 12-byte random nonce
     */
    public static byte[] generateNonce() {
        java.security.SecureRandom random = new java.security.SecureRandom();
        byte[] nonce = new byte[12];
        random.nextBytes(nonce);
        return nonce;
    }

    // ========================================================================
    // ML-KEM-1024 (Kyber-1024) Post-Quantum Key Encapsulation
    // ========================================================================

    /**
     * Generate ML-KEM-1024 keypair
     *
     * @return Object[] {publicKey (1568 bytes), secretKey (3168 bytes)}
     */
    public native Object[] mlkemKeypair();

    /**
     * ML-KEM-1024 Encapsulation
     *
     * Generate shared secret and encapsulate with public key
     *
     * @param publicKey 1568-byte ML-KEM public key
     * @return Object[] {ciphertext (1568 bytes), sharedSecret (32 bytes)}
     */
    public native Object[] mlkemEncapsulate(byte[] publicKey);

    /**
     * ML-KEM-1024 Decapsulation
     *
     * Recover shared secret from ciphertext using secret key
     *
     * @param ciphertext 1568-byte ML-KEM ciphertext
     * @param secretKey 3168-byte ML-KEM secret key
     * @return 32-byte shared secret, or null if decapsulation fails
     */
    public native byte[] mlkemDecapsulate(byte[] ciphertext, byte[] secretKey);
}
