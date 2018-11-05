package com.felix.cipherlibrary.des;

import com.felix.cipherlibrary.encode.Base64;

import java.security.Key;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.IvParameterSpec;


/**
 * 3DES encryption tool class
 * https://www.cnblogs.com/oc-bowen/p/5622914.html
 * Encryption and decryption can be successful.
 */
public class Des3Util {
    // 密钥 长度不得小于24
    private final static String SECRET_KEY = "123456789012345678901234";
    // 向量 可有可无 终端后台也要约定
    private final static String iv = "01234567";
    // Coding method for encryption and decryption
    private final static String encoding = "utf-8";

    /**
     * 3DES加密
     *
     * @param plainText plainText
     * @param secretKey String
     * @return String
     * @throws Exception Exception
     */
    public static String encode(String secretKey, String plainText) throws Exception {
        Key deskey = null;
        DESedeKeySpec spec = new DESedeKeySpec(secretKey.getBytes());
        SecretKeyFactory keyfactory = SecretKeyFactory.getInstance("desede");
        deskey = keyfactory.generateSecret(spec);

        Cipher cipher = Cipher.getInstance("desede/CBC/PKCS5Padding");
        IvParameterSpec ips = new IvParameterSpec(iv.getBytes());
        cipher.init(Cipher.ENCRYPT_MODE, deskey, ips);
        byte[] encryptData = cipher.doFinal(plainText.getBytes(encoding));
        return Base64.encode(encryptData);
    }

    /**
     * 3DES解密
     *
     * @param secretKey   String
     * @param encryptText 加密文本
     * @return String
     */
    public static String decode(String secretKey, String encryptText) {
        try {
            Key deskey;
            DESedeKeySpec spec = new DESedeKeySpec(secretKey.getBytes());
            SecretKeyFactory keyfactory = SecretKeyFactory.getInstance("desede");
            deskey = keyfactory.generateSecret(spec);
            Cipher cipher = Cipher.getInstance("desede/CBC/PKCS5Padding");
            IvParameterSpec ips = new IvParameterSpec(iv.getBytes());
            cipher.init(Cipher.DECRYPT_MODE, deskey, ips);

            byte[] decryptData = cipher.doFinal(Base64.decode(encryptText));

            return new String(decryptData, encoding);
        } catch (Exception e) {
            e.printStackTrace();
            return "";
        }
    }

    public static void main(String args[]) throws Exception {
        // 密钥 长度不得小于24
        String secretKey = "123456789012345678901234";
        String str = "123456";
        System.out.println("----after encode-----:" + str);
        String encodeStr = Des3Util.encode(secretKey, str);
        System.out.println("----after encode-----:" + encodeStr);
        System.out.println("----after decode-----:" + Des3Util.decode(secretKey, encodeStr));
    }
}
