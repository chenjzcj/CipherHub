package com.felix.cipherlibrary.rsa;


import com.blankj.utilcode.util.LogUtils;
import com.felix.cipherlibrary.Base64;

import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;

/**
 * Created by Felix.Zhong on 2018/8/22 14:30
 * RSA非对称加密工具类
 */
public class RSAUtils {
    /**
     * 构建Cipher实例时所传入的的字符串，默认为"RSA/NONE/PKCS1Padding"
     */
    private static String sTransform = "RSA/NONE/PKCS1Padding";

    private static String TRANSFORMATION_RSA = "RSA";

    /**
     * 进行Base64转码时的flag设置，默认为Base64.DEFAULT
     */
    private static int sBase64Mode = Base64.DEFAULT;

    /**
     * 初始化方法，设置参数
     */
    public static void init(String transform, int base64Mode) {
        sTransform = transform;
        sBase64Mode = base64Mode;
    }

    /**
     * 随机生成RSA密钥对，包括PublicKey，PrivateKey
     *
     * @param keyLength 密钥对长度，范围是 512~2048，一般是1024，
     *                  如果小于512会报错：java.security.InvalidParameterException: RSA keys must be at least 512 bits long
     * @return KeyPair 生成的密钥对
     */
    public static KeyPair generateRSAKeyPair(int keyLength) {
        keyLength = keyLength < 512 ? 512 : keyLength;
        KeyPair keyPair = null;
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            //设置密钥长度
            keyPairGenerator.initialize(keyLength);
            //产生密钥对
            keyPair = keyPairGenerator.genKeyPair();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return keyPair;
    }


    /**
     * 加密或解密数据的通用的方法
     *
     * @param srcData 待处理的数据
     * @param key     公钥或者私钥
     * @param mode    指加密还是解密，值为Cipher.ENCRYPT_MODE或者Cipher.DECRYPT_MODE
     * @return 处理后的字节数组
     */
    private static byte[] processData(byte[] srcData, Key key, int mode) {
        //用来保存处理的结果
        byte[] resultBytes = null;
        //构建Cipher对象，需要传入一个字符串，格式必须为"algorithm/mode/padding"或者"algorithm/",意为"算法/加密模式/填充方式"
        try {
            Cipher cipher = Cipher.getInstance(TRANSFORMATION_RSA);
            //初始化Cipher,mode指定是加密还是解密，key为公钥或密钥
            cipher.init(mode, key);
            //处理数据
            resultBytes = cipher.doFinal(srcData);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return resultBytes;
    }

    /**
     * 使用公钥加密数据，结果用Base64转码
     *
     * @param srcData   待处理的数据
     * @param publicKey 公钥
     * @return 加密后的数据
     */
    public static String encryptDataByPublicKey(byte[] srcData, PublicKey publicKey) {
        byte[] resultBytes = processData(srcData, publicKey, Cipher.ENCRYPT_MODE);
        return Base64.encodeToString(resultBytes, sBase64Mode);
    }

    /**
     * 使用私钥解密，结果用Base64转码
     *
     * @param encryptedData 待处理的数据
     * @param privateKey    私钥
     * @return 解密后的字节数组
     */
    public static byte[] decryptDataByPrivate(String encryptedData, PrivateKey privateKey) {
        byte[] bytes = Base64.decode(encryptedData, sBase64Mode);
        return processData(bytes, privateKey, Cipher.DECRYPT_MODE);
    }

    /**
     * 使用私钥解密，返回解码数据
     *
     * @param encryptedData 待处理的数据
     * @param privateKey    私钥
     * @return 解密后的字符串
     */
    public static String decryptToStrByPrivate(String encryptedData, PrivateKey privateKey) {
        return new String(decryptDataByPrivate(encryptedData, privateKey));
    }


    /**
     * 通过公钥进行RSA解密
     *
     * @param key  解密公钥
     * @param data 需要解密的密文
     * @return 解密出来的结果
     */
    public static String decryptDataByPublic(String key, String data) {
        String signature = "";
        try {
            byte[] keyBytes = com.felix.cipherlibrary.encode.Base64.decode(key);
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PublicKey publicKey = keyFactory.generatePublic(keySpec);

            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            byte[] encryptBytes = cipher.doFinal(data.getBytes());
            signature = com.felix.cipherlibrary.encode.Base64.encode(encryptBytes);
        } catch (Exception e) {
            LogUtils.i("RSA解密的时候报错啦 e = " + e);
        }
        return signature;
    }
}
