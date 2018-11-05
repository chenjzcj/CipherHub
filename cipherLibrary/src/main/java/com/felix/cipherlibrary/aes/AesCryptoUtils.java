package com.felix.cipherlibrary.aes;

import com.tozny.crypto.android.AesCbcWithIntegrity;

/**
 * Created by Felix.Zhong on 2018/10/7 15:53
 * AES symmetric encryption encapsulation final solution https://github.com/tozny/java-aes-crypto tool class
 */
public class AesCryptoUtils {

    /**
     * 加密
     *
     * @param plaintext Encrypted original text
     * @return Encrypted string
     */
    public static String encrypt(String plaintext) {
        String ciphertextString = "";
        try {
            AesCbcWithIntegrity.SecretKeys keys = AesCbcWithIntegrity.generateKey();
            AesCbcWithIntegrity.CipherTextIvMac cipherTextIvMac = AesCbcWithIntegrity.encrypt(plaintext, keys);
            //store or send to server
            ciphertextString = cipherTextIvMac.toString();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return ciphertextString;
    }

    /**
     * 加密
     *
     * @param plaintext Encrypted original text
     * @param password  password
     * @return Encrypted string
     */
    public static String encrypt(String plaintext, String password) {
        String ciphertextString = "";
        try {
            AesCbcWithIntegrity.SecretKeys keys = AesCbcWithIntegrity.generateKeyFromPassword(password, "eee");
            AesCbcWithIntegrity.CipherTextIvMac cipherTextIvMac = AesCbcWithIntegrity.encrypt(plaintext, keys);
            //store or send to server
            ciphertextString = cipherTextIvMac.toString();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return ciphertextString;
    }

    /**
     * 解密
     *
     * @param base64IvAndCiphertext base64处理过的密文
     * @return 原文
     */
    public static String decryptString(String base64IvAndCiphertext) {
        String plainText = "";
        try {
            AesCbcWithIntegrity.SecretKeys keys = AesCbcWithIntegrity.generateKey();
            //Use the constructor to re-create the CipherTextIvMac class from the string:
            AesCbcWithIntegrity.CipherTextIvMac cipherTextIvMac = new AesCbcWithIntegrity.CipherTextIvMac(base64IvAndCiphertext);
            plainText = AesCbcWithIntegrity.decryptString(cipherTextIvMac, keys);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return plainText;
    }

    /**
     * 解密
     *
     * @param base64IvAndCiphertext base64处理过的密文
     * @param password              解密私钥
     * @return 原文
     */
    public static String decryptString(String base64IvAndCiphertext, String password) {
        String plainText = "";
        try {
            AesCbcWithIntegrity.SecretKeys keys = AesCbcWithIntegrity.generateKeyFromPassword(password, "eee");
            //Use the constructor to re-create the CipherTextIvMac class from the string:
            AesCbcWithIntegrity.CipherTextIvMac cipherTextIvMac = new AesCbcWithIntegrity.CipherTextIvMac(base64IvAndCiphertext);
            plainText = AesCbcWithIntegrity.decryptString(cipherTextIvMac, keys);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return plainText;
    }
}
