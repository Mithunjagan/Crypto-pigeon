package app.cryptopigeon.nativeclient;

import java.security.MessageDigest;

/** Platform-independent seven-of-seven primitive, shared by Android and JVM verification. */
final class SevenShares {
    static byte[][] split(byte[] wrapped){
        if(wrapped.length!=48)throw new IllegalArgumentException("invalid_wrapped_vmk");
        byte[][] shares=new byte[7][];shares[6]=wrapped.clone();for(int i=0;i<6;i++){shares[i]=Crypto.random(48);for(int j=0;j<48;j++)shares[6][j]^=shares[i][j];}return shares;
    }
    static byte[] collect(byte[][] shares,byte[][] hashes){
        if(shares.length!=7||hashes.length!=7)throw new IllegalStateException("HORCRUX_INCOMPLETE_RESTORE_REQUIRED");
        for(int i=0;i<7;i++)if(shares[i]==null||shares[i].length!=48||hashes[i]==null||!MessageDigest.isEqual(Crypto.sha256(shares[i]),hashes[i]))throw new IllegalStateException("HORCRUX_INCOMPLETE_RESTORE_REQUIRED");
        byte[] result=new byte[48];for(byte[] share:shares)for(int j=0;j<48;j++)result[j]^=share[j];return result;
    }
}
