package com.felix.cipherlibrary.aes;


import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Created by Felix.Zhong on 2018/7/26 17:53
 * <p>
 * AES 对称加密
 * 高级加密标准（英语：Advanced Encryption Standard，缩写：AES），在密码学中又称Rijndael加密法，
 * 是美国联邦政府采用的一种区块加密标准。 这个标准用来替代原先的DES，已经被多方分析且广为全世界所使用。
 * Android 中的AES 加密 秘钥 key 必须为16/24/32位字节，否则抛异常
 * <p>
 * 总结：
 * AES对称加密，加解密相比于亦或加密还是有点复杂的，安全性也比亦或加密高，AES加密不是绝对的安全。
 * <p>
 * 功能说明：对文件进行AES加密（验证可用）
 */
public class AESForFile {
    private static final String TAG = "AES";
    /**
     * 加密
     */
    private final static int MODE_ENCRYPTION = 1;
    /**
     * 解密
     */
    private final static int MODE_DECRYPTION = 2;
    /**
     * AES 秘钥key，必须为16位
     */
    private final static String AES_KEY = "xjp_12345!^-=42#";


    /**
     * AES 加密
     *
     * @param source 需要加密的文件路径
     * @param dest   加密后的文件路径
     */
    public static void encryptByAES(String source, String dest) {
        encryptByAES(MODE_ENCRYPTION, source, dest);
    }

    /**
     * AES 解密
     *
     * @param source 需要解密的文件路径
     * @param dest   解密后保存的文件路径
     */
    public static void decryptByAES(String source, String dest) {
        encryptByAES(MODE_DECRYPTION, source, dest);
    }

    private static void encryptByAES(int mode, String source, String dest) {
        //Log.i(TAG, "start===encryptByAES");
        System.out.print("start===encryptByAES");
        FileInputStream fis = null;
        FileOutputStream fos = null;
        try {
            fis = new FileInputStream(source);
            fos = new FileOutputStream(dest);
            int size = 2048;
            byte[] buff = new byte[size];
            byte[] buffResult;
            while ((fis.read(buff)) != -1) {
                buffResult = encryption(mode, buff, AES_KEY);
                if (buffResult != null) {
                    fos.write(buffResult);
                }
            }
            //Log.i(TAG, "end===encryptByAES");
            System.out.print("end===encryptByAES");
        } catch (IOException e) {
            e.printStackTrace();
            //Log.e(TAG, "encryptByAES failed err: " + e.getMessage());
            System.out.print("encryptByAES failed err: " + e.getMessage());
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

    private static byte[] encryption(int mode, byte[] content, String pwd) {
        try {
            //AES加密模式，CFB 加密模式
            Cipher cipher = Cipher.getInstance("AES/CFB/NoPadding");
            //AES加密方式
            SecretKeySpec keySpec = new SecretKeySpec(pwd.getBytes("UTF-8"), "AES");
            IvParameterSpec ivSpec = new IvParameterSpec(pwd.getBytes("UTF-8"));
            cipher.init(mode == MODE_ENCRYPTION ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE, keySpec, ivSpec);
            return cipher.doFinal(content);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException |
                InvalidKeyException | IllegalBlockSizeException |
                BadPaddingException | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
            //Log.e(TAG, "encryption failed... err: " + e.getMessage());
            System.out.print("encryption failed... err: " + e.getMessage());
        } catch (Exception e) {
            e.printStackTrace();
            //Log.e(TAG, "encryption1 failed ...err: " + e.getMessage());
            System.out.print("encryption1 failed ...err: " + e.getMessage());
        }
        return null;
    }

    public static void main(String[] args) {
        //encryptByAES("i://source.txt", "i://dest.txt");
        decryptByAES("i://dest.txt", "i://pla.txt");
    }
}
