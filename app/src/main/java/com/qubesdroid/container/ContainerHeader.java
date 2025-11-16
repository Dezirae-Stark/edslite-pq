package com.qubesdroid.container;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;

/**
 * QubesDroid Container Header Structure
 *
 * Offset   Size    Description
 * ------   ----    -----------
 * 0        4       Magic: "QBES"
 * 4        2       Version (0x0100)
 * 6        2       Flags (reserved)
 * 8        8       Volume Size (bytes)
 * 16       4       Argon2 Time Cost
 * 20       4       Argon2 Memory Cost (KB)
 * 24       4       Argon2 Parallelism
 * 28       4       Reserved
 * 32       32      Salt (Argon2id)
 * 64       1568    ML-KEM-1024 Ciphertext
 * 1632     12      ChaCha20 Nonce
 * 1644     32      Encrypted Master Key
 * 1676     16      Poly1305 MAC
 * 1692     32      Hidden Volume Offset (encrypted, 0 if no hidden volume)
 * 1724     32      Hidden Volume Size (encrypted, 0 if no hidden volume)
 * 1756     ...     Reserved (zero-filled)
 * 32768    32768   Backup Header (mirror of above)
 */
public class ContainerHeader
{
    // Constants
    public static final int HEADER_SIZE = 65536; // 64 KB total
    public static final int PRIMARY_HEADER_SIZE = 32768; // 32 KB
    public static final int BACKUP_HEADER_OFFSET = 32768; // 32 KB

    private static final byte[] MAGIC = {'Q', 'B', 'E', 'S'};
    private static final short VERSION = 0x0100;

    // Header fields
    private long volumeSize;
    private int argon2TimeCost;
    private int argon2MemoryCost;
    private int argon2Parallelism;
    private byte[] salt;
    private byte[] mlkemCiphertext;
    private byte[] chacha20Nonce;
    private byte[] encryptedMasterKey;
    private byte[] poly1305Mac;
    private long hiddenVolumeOffset;
    private long hiddenVolumeSize;

    public ContainerHeader()
    {
        salt = new byte[32];
        mlkemCiphertext = new byte[1568];
        chacha20Nonce = new byte[12];
        encryptedMasterKey = new byte[32];
        poly1305Mac = new byte[16];
        hiddenVolumeOffset = 0;
        hiddenVolumeSize = 0;
    }

    /**
     * Serialize header to bytes
     */
    public byte[] toBytes() throws IOException
    {
        ByteBuffer buffer = ByteBuffer.allocate(PRIMARY_HEADER_SIZE);
        buffer.order(ByteOrder.LITTLE_ENDIAN);

        // Magic signature
        buffer.put(MAGIC);

        // Version
        buffer.putShort(VERSION);

        // Flags (reserved)
        buffer.putShort((short) 0);

        // Volume size
        buffer.putLong(volumeSize);

        // Argon2 parameters
        buffer.putInt(argon2TimeCost);
        buffer.putInt(argon2MemoryCost);
        buffer.putInt(argon2Parallelism);

        // Reserved
        buffer.putInt(0);

        // Salt
        buffer.put(salt);

        // ML-KEM ciphertext
        buffer.put(mlkemCiphertext);

        // ChaCha20 nonce
        buffer.put(chacha20Nonce);

        // Encrypted master key
        buffer.put(encryptedMasterKey);

        // Poly1305 MAC
        buffer.put(poly1305Mac);

        // Hidden volume info (encrypted separately)
        ByteBuffer hiddenInfo = ByteBuffer.allocate(16);
        hiddenInfo.order(ByteOrder.LITTLE_ENDIAN);
        hiddenInfo.putLong(hiddenVolumeOffset);
        hiddenInfo.putLong(hiddenVolumeSize);
        buffer.put(hiddenInfo.array());

        // Fill remaining with zeros
        int remaining = PRIMARY_HEADER_SIZE - buffer.position();
        buffer.put(new byte[remaining]);

        return buffer.array();
    }

    /**
     * Parse header from bytes
     */
    public static ContainerHeader fromBytes(byte[] data) throws IOException
    {
        if (data.length < PRIMARY_HEADER_SIZE)
        {
            throw new IOException("Invalid header size");
        }

        ByteBuffer buffer = ByteBuffer.wrap(data);
        buffer.order(ByteOrder.LITTLE_ENDIAN);

        ContainerHeader header = new ContainerHeader();

        // Verify magic
        byte[] magic = new byte[4];
        buffer.get(magic);
        if (!Arrays.equals(magic, MAGIC))
        {
            throw new IOException("Invalid QubesDroid container: bad magic signature");
        }

        // Version
        short version = buffer.getShort();
        if (version != VERSION)
        {
            throw new IOException("Unsupported container version: " + Integer.toHexString(version));
        }

        // Flags
        buffer.getShort(); // reserved

        // Volume size
        header.volumeSize = buffer.getLong();

        // Argon2 parameters
        header.argon2TimeCost = buffer.getInt();
        header.argon2MemoryCost = buffer.getInt();
        header.argon2Parallelism = buffer.getInt();

        // Reserved
        buffer.getInt();

        // Salt
        buffer.get(header.salt);

        // ML-KEM ciphertext
        buffer.get(header.mlkemCiphertext);

        // ChaCha20 nonce
        buffer.get(header.chacha20Nonce);

        // Encrypted master key
        buffer.get(header.encryptedMasterKey);

        // Poly1305 MAC
        buffer.get(header.poly1305Mac);

        // Hidden volume info
        header.hiddenVolumeOffset = buffer.getLong();
        header.hiddenVolumeSize = buffer.getLong();

        return header;
    }

    // Getters and setters
    public long getVolumeSize() { return volumeSize; }
    public void setVolumeSize(long size) { this.volumeSize = size; }

    public int getArgon2TimeCost() { return argon2TimeCost; }
    public void setArgon2TimeCost(int cost) { this.argon2TimeCost = cost; }

    public int getArgon2MemoryCost() { return argon2MemoryCost; }
    public void setArgon2MemoryCost(int cost) { this.argon2MemoryCost = cost; }

    public int getArgon2Parallelism() { return argon2Parallelism; }
    public void setArgon2Parallelism(int threads) { this.argon2Parallelism = threads; }

    public byte[] getSalt() { return salt; }
    public void setSalt(byte[] salt) { this.salt = salt; }

    public byte[] getMlkemCiphertext() { return mlkemCiphertext; }
    public void setMlkemCiphertext(byte[] ct) { this.mlkemCiphertext = ct; }

    public byte[] getChacha20Nonce() { return chacha20Nonce; }
    public void setChacha20Nonce(byte[] nonce) { this.chacha20Nonce = nonce; }

    public byte[] getEncryptedMasterKey() { return encryptedMasterKey; }
    public void setEncryptedMasterKey(byte[] key) { this.encryptedMasterKey = key; }

    public byte[] getPoly1305Mac() { return poly1305Mac; }
    public void setPoly1305Mac(byte[] mac) { this.poly1305Mac = mac; }

    public long getHiddenVolumeOffset() { return hiddenVolumeOffset; }
    public void setHiddenVolumeOffset(long offset) { this.hiddenVolumeOffset = offset; }

    public long getHiddenVolumeSize() { return hiddenVolumeSize; }
    public void setHiddenVolumeSize(long size) { this.hiddenVolumeSize = size; }
}
