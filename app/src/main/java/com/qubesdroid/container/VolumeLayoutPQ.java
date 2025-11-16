package com.qubesdroid.container;

import com.sovworks.eds.container.VolumeLayout;
import com.sovworks.eds.crypto.EncryptionEngine;
import com.sovworks.eds.crypto.SecureBuffer;
import com.qubesdroid.crypto.CryptoNative;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

/**
 * QubesDroid Post-Quantum Volume Layout
 *
 * Container Structure:
 * [0-65535]     Header Section (64 KB)
 *   [0-3]       Magic: "QBES"
 *   [4-5]       Version: 0x0100
 *   [6-1573]    ML-KEM-1024 Ciphertext (1568 bytes)
 *   [1574-...]  ChaCha20-Poly1305 Encrypted Header
 * [65536-...]   Data Section (ChaCha20 encrypted)
 */
public class VolumeLayoutPQ extends VolumeLayout
{
    // Constants
    private static final byte[] MAGIC_SIGNATURE = {'Q', 'B', 'E', 'S'};
    private static final short VERSION = 0x0100; // v1.0

    private static final int HEADER_SIZE = 65536; // 64 KB
    private static final int ML_KEM_CT_SIZE = 1568; // ML-KEM-1024 ciphertext
    private static final int SALT_SIZE = 32;
    private static final int NONCE_SIZE = 12; // ChaCha20 nonce
    private static final int MASTER_KEY_SIZE = 32;
    private static final int MAC_SIZE = 16; // Poly1305 tag

    // Argon2id parameters (adjustable)
    private int _argon2_time_cost = 3;  // iterations
    private int _argon2_memory_cost = 65536; // 64 MB
    private int _argon2_parallelism = 4; // threads

    private CryptoNative crypto;
    private byte[] masterKey;
    private boolean isHiddenVolume;

    public VolumeLayoutPQ()
    {
        crypto = new CryptoNative();
        isHiddenVolume = false;
    }

    @Override
    protected byte[] getHeaderSignature()
    {
        return MAGIC_SIGNATURE;
    }

    @Override
    protected short getMinCompatibleProgramVersion()
    {
        return VERSION;
    }

    @Override
    public int getHeaderSize()
    {
        return HEADER_SIZE;
    }

    /**
     * Generate master key using ML-KEM-1024 + Argon2id
     */
    public byte[] generateMasterKey(String password, byte[] salt) throws IOException
    {
        try
        {
            // Derive key from password using Argon2id
            byte[] derivedKey = crypto.deriveKey(
                password.getBytes("UTF-8"),
                salt,
                MASTER_KEY_SIZE,
                _argon2_time_cost,
                _argon2_memory_cost,
                _argon2_parallelism
            );

            // Generate ML-KEM-1024 keypair
            byte[][] keypair = crypto.generateMLKEMKeypair();
            byte[] publicKey = keypair[0];
            byte[] secretKey = keypair[1];

            // Encapsulate to get shared secret
            byte[][] encapsulated = crypto.mlkemEncapsulate(publicKey);
            byte[] sharedSecret = encapsulated[0];
            byte[] ciphertext = encapsulated[1];

            // Combine derived key with shared secret using BLAKE2s
            byte[] combined = new byte[derivedKey.length + sharedSecret.length];
            System.arraycopy(derivedKey, 0, combined, 0, derivedKey.length);
            System.arraycopy(sharedSecret, 0, combined, derivedKey.length, sharedSecret.length);

            masterKey = crypto.hash(combined);

            // Securely erase sensitive data
            Arrays.fill(derivedKey, (byte) 0);
            Arrays.fill(sharedSecret, (byte) 0);
            Arrays.fill(combined, (byte) 0);
            Arrays.fill(secretKey, (byte) 0);

            return masterKey;
        }
        catch (Exception e)
        {
            throw new IOException("Failed to generate master key: " + e.getMessage(), e);
        }
    }

    /**
     * Set Argon2id parameters (for advanced users)
     */
    public void setArgon2Parameters(int timeCost, int memoryCost, int parallelism)
    {
        _argon2_time_cost = timeCost;
        _argon2_memory_cost = memoryCost;
        _argon2_parallelism = parallelism;
    }

    /**
     * Enable hidden volume mode
     */
    public void setHiddenVolume(boolean hidden)
    {
        isHiddenVolume = hidden;
    }

    public boolean isHiddenVolume()
    {
        return isHiddenVolume;
    }

    @Override
    public void close() throws IOException
    {
        super.close();

        // Securely erase master key
        if (masterKey != null)
        {
            Arrays.fill(masterKey, (byte) 0);
            masterKey = null;
        }
    }
}
