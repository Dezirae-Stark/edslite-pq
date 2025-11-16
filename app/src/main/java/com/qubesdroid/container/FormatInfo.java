package com.qubesdroid.container;

import com.sovworks.eds.container.ContainerFormatInfo;
import com.sovworks.eds.container.VolumeLayout;

/**
 * QubesDroid Pure Post-Quantum Container Format
 *
 * Features:
 * - ML-KEM-1024 key encapsulation
 * - ChaCha20-Poly1305 authenticated encryption
 * - Argon2id key derivation
 * - BLAKE2s-256 hashing
 * - Hidden volume support
 * - Dynamic volume sizing
 */
public class FormatInfo extends ContainerFormatInfo
{
    public static final String FORMAT_NAME = "QubesDroid-PQ";
    public static final String FORMAT_VERSION = "1.0.0";

    // QubesDroid magic signature: "QBES"
    public static final byte[] MAGIC_SIGNATURE = {'Q', 'B', 'E', 'S'};

    // Format capabilities
    public static final int MIN_VOLUME_SIZE = 1024 * 1024; // 1 MB
    public static final long MAX_VOLUME_SIZE = 2L * 1024 * 1024 * 1024 * 1024; // 2 TB
    public static final int HEADER_SIZE = 65536; // 64 KB

    @Override
    public String getFormatName()
    {
        return FORMAT_NAME;
    }

    public String getFormatVersion()
    {
        return FORMAT_VERSION;
    }

    @Override
    public VolumeLayout getVolumeLayout()
    {
        return new com.qubesdroid.container.VolumeLayoutPQ();
    }

    @Override
    public int getOpeningPriority()
    {
        // Highest priority - try QubesDroid format first
        return 10;
    }

    @Override
    public boolean hasCustomKDFIterationsSupport()
    {
        // Argon2id with configurable time/memory parameters
        return true;
    }

    @Override
    public boolean requiresFormatter()
    {
        return true;
    }

    public boolean supportsHiddenVolumes()
    {
        return true;
    }

    public boolean supportsKeyfiles()
    {
        return true;
    }

    public boolean supportsBiometric()
    {
        return true;
    }
}
