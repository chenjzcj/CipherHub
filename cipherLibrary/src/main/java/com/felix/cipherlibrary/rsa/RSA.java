package com.felix.cipherlibrary.rsa;

import android.util.Base64;
import android.util.Log;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;

/**
 * Created by Felix.Zhong on 2018/7/26 18:10
 * https://blog.csdn.net/feiduclear_up/article/details/73604507
 * <p>
 * 什么是RSA加密？
 * <p>
 * RSA算法是最流行的公钥密码算法，使用长度可以变化的密钥。RSA是第一个既能用于数据加密也能用于数字签名的算法。
 * <p>
 * RSA的安全性依赖于大数分解，小于1024位的N已经被证明是不安全的，而且由于RSA算法进行的都是大数计算，
 * 使得RSA最快的情况也比DES慢上倍，这是RSA最大的缺陷，因此通常只能用于加密少量数据或者加密密钥，但RSA仍然不失为一种高强度的算法。
 * <p>
 * 总结：
 * 1.AES公钥加密，私钥解密
 * 2.AES加密耗时
 * 3.AES加密后数据会变大
 */
public class RSA {
    /**************************************************
     * 1.什么是RSA 非对称加密？
     * <p>
     * 2.
     *************************************************/

    private static final String TAG = "EncryptUtils";

    /**
     * 加密方式 RSA
     */
    private final static String RSA = "RSA";

    private final static int DEFAULT_KEY_SIZE = 1024;
    /**
     * 解密长度
     */
    private final static int DECRYPT_LEN = DEFAULT_KEY_SIZE / 8;
    /**
     * 加密长度
     */
    private final static int ENCRYPT_LEN = DECRYPT_LEN - 11;
    /**
     * 加密填充方式
     */
    private static final String DES_CBC_PKCS5PAD = "DES/CBC/PKCS5Padding";
    //私钥加密
    private final static int MODE_PRIVATE = 1;
    //公钥加密
    private final static int MODE_PUBLIC = 2;

    /**
     * RSA加密文件
     *
     * @param source 需要加密的文件路径
     * @param dest   加密后文件路径
     * @param key    加密的key
     */
    public static void encryptFileByRSA(String source, String dest, Key key) {
        rsaEncrypt(Cipher.ENCRYPT_MODE, source, dest, key);
    }

    /**
     * RSA解密文件
     *
     * @param source 需要解密的文件路径
     * @param dest   解密后文件路径
     * @param key    解密的key
     */
    public static void decrypFileByRSA(String source, String dest, Key key) {
        rsaEncrypt(Cipher.DECRYPT_MODE, source, dest, key);
    }

    /**
     * RSA加解密
     *
     * @param mode   加解密模式
     * @param source 需要处理的文件路径
     * @param dest   处理后的文件路径
     * @param key    加解密的key
     */
    private static void rsaEncrypt(int mode, String source, String dest, Key key) {
        Log.i(TAG, "start===encryptByRSA mode--->>" + mode);
        FileInputStream fis = null;
        FileOutputStream fos = null;
        try {
            fis = new FileInputStream(source);
            fos = new FileOutputStream(dest);
            int size = (mode == Cipher.ENCRYPT_MODE ? ENCRYPT_LEN : DECRYPT_LEN);
            byte[] buff = new byte[size];
            byte[] buffResult;
            while ((fis.read(buff)) != -1) {
                buffResult = (mode == Cipher.ENCRYPT_MODE ? encryptByRSA(buff, key) : decryptByRSA(buff, key));
                if (buffResult != null) {
                    fos.write(buffResult);
                }
            }
            Log.i(TAG, "end===encryptByRSA");
        } catch (IOException e) {
            e.printStackTrace();
            Log.e(TAG, "encryptByRSA failed err: " + e.getMessage());
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            try {
                if (fis != null) {
                    fis.close();
                }
                if (fos != null) {
                    fos.close();
                }
            } catch (IOException e) {
                e.printStackTrace();
            }

        }
    }

    /**
     * 私钥加密
     *
     * @param data 需要被加密的数据
     * @param key  私钥
     * @return 加密后的数据
     * @throws Exception 异常
     */
    private static byte[] encryptByRSA(byte[] data, Key key) throws Exception {
        // 数据加密
        Cipher cipher = Cipher.getInstance(RSA);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(data);
    }


    /**
     * 公钥解密
     *
     * @param data 待解密数据
     * @param key  密钥
     * @return byte[] 解密数据
     */
    private static byte[] decryptByRSA(byte[] data, Key key) throws Exception {
        // 数据解密
        Cipher cipher = Cipher.getInstance(RSA);
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(data);
    }


    /**
     * 得到私钥
     *
     * @param key 秘钥
     * @return PrivateKey 私钥
     * @throws NoSuchAlgorithmException 没有这样的算法异常
     * @throws InvalidKeySpecException  无效的密钥规范异常
     */
    public static PrivateKey getPrivateKey(String key) throws NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] privateKey = Base64.decode(key, Base64.URL_SAFE);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKey);
        KeyFactory kf = KeyFactory.getInstance(RSA);
        return kf.generatePrivate(keySpec);
    }

    /**
     * 得到公钥
     *
     * @param key 秘钥
     * @return PublicKey 公钥
     * @throws NoSuchAlgorithmException 没有这样的算法异常
     * @throws InvalidKeySpecException  无效的密钥规范异常
     */
    public static PublicKey getPublicKey(String key) throws NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] publicKey = Base64.decode(key, Base64.URL_SAFE);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKey);
        KeyFactory kf = KeyFactory.getInstance(RSA);
        return kf.generatePublic(keySpec);
    }
}
