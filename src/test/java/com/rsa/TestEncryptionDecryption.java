package com.rsa;

import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.Map;

import com.rsa.util.FileUtil;
import com.rsa.util.RandomUtil;
import com.rsa.util.EncryptionDecryptionUtil;
import org.junit.Assert;
import org.junit.Test;

public class TestEncryptionDecryption {
  @Test
  public final void encryptDecryptTest() {
    int n = 5;
    int k = 2;
    final String secret = RandomUtil.generateString(16);

    System.out.println("Random secret key : " + secret);

    // Creates the RSA key pair, shards, and saves files
    final Map<Integer, byte[]> privateKeyParts = EncryptionDecryption.generateShardedKey(n, k);

    // load public key from file
    final byte[] publicKeyBytes = FileUtil.readFileHexFormat("Public.TXT");
    final PublicKey publicKey = EncryptionDecryptionUtil.buildPublicKey(publicKeyBytes);

    // Reassembles the Private Key using shard 2 & 5. from files
    final byte[] shard2 = FileUtil.readFileHexFormat("Shard[2].TXT");
    final byte[] shard5 = FileUtil.readFileHexFormat("Shard[5].TXT");
    final Map<Integer, byte[]> parts = new HashMap<>();
    parts.put(2, shard2);
    parts.put(5, shard5);

    // use parts to recover private key
    byte[] privateKeyBytes = EncryptionDecryptionUtil.shamirJoin(n, k, parts);
    final PrivateKey recoveredPrivateKey = EncryptionDecryptionUtil.buildPrivateKey(privateKeyBytes);

    // decrypt encrypted data using recovered private key
    byte[] encryptedData = EncryptionDecryptionUtil.encrypt(publicKey, secret.getBytes());
    final byte[] decryptedData = EncryptionDecryptionUtil.decrypt(recoveredPrivateKey, encryptedData);
    final String decryptedSecret = new String(decryptedData, StandardCharsets.UTF_8);
    System.out.println("After decryption recovered secret key : " + decryptedSecret);

    Assert.assertEquals(secret, decryptedSecret);
  }

}
