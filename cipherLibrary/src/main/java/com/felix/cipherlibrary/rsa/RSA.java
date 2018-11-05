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
 * What is RSA encryption?
 * <p>
 * RSA algorithm is the most popular public key cryptography algorithm, using the key that can be changed in length.
 * RSA is the first algorithm that can be used both for data encryption and for digital signature.
 * <p>
 * The security of RSA depends on large number decomposition. N less than 1024 bits has been proved to be unsafe, and because RSA algorithm performs large number calculation.
 * The fastest RSA is twice as slow as DES, which is the biggest drawback of RSA, so it can only be used to encrypt a small amount of data or encryption keys, but RSA is still a high-strength algorithm.
 * <p>
 * summary:
 * 1.AES public key encryption, private key decryption
 * 2.AES加密耗时
 * 3.AES加密后数据会变大
 */
public class RSA {
    /**************************************************
     * 1.What is RSA asymmetric encryption?
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
     * @param source Encrypted file path
     * @param dest   Encrypted file path
     * @param key    加密的key
     */
    public static void encryptFileByRSA(String source, String dest, Key key) {
        rsaEncrypt(Cipher.ENCRYPT_MODE, source, dest, key);
    }

    /**
     * RSA解密文件
     *
     * @param source File path to be decrypted
     * @param dest   File path after declassified
     * @param key    解密的key
     */
    public static void decrypFileByRSA(String source, String dest, Key key) {
        rsaEncrypt(Cipher.DECRYPT_MODE, source, dest, key);
    }

    /**
     * RSA encryption and decryption
     *
     * @param mode   Encryption and decryption mode
     * @param source File path to be processed
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
     * @param data Data that needs to be encrypted
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
     * @param data Data to be decrypted
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
     * @throws NoSuchAlgorithmException No such algorithm is abnormal.
     * @throws InvalidKeySpecException  Invalid key specification exception
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
     * @throws NoSuchAlgorithmException No such algorithm is abnormal.
     * @throws InvalidKeySpecException  Invalid key specification exception
     */
    public static PublicKey getPublicKey(String key) throws NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] publicKey = Base64.decode(key, Base64.URL_SAFE);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKey);
        KeyFactory kf = KeyFactory.getInstance(RSA);
        return kf.generatePublic(keySpec);
    }
}
