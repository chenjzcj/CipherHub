package com.tok.aesdemo;

import com.tozny.crypto.android.AesCbcWithIntegrity;

/**
 * Created by Felix.Zhong on 2018/10/7 15:53
 * AES对称加密封装最终解决方案 https://github.com/tozny/java-aes-crypto 工具类
 */
public class AesCryptoUtils {

    /**
     * 加密
     *
     * @param plaintext 需要加密的原文
     * @return 加密后的字符串
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
