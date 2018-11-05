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
 * It is a block encryption standard adopted by the federal government of the United States. This standard is used to replace the original DES, which has been widely analyzed and widely used all over the world.
 * The AES encryption secret key key in Android must be 16/24/32 bit bytes, otherwise throw exceptions.
 * <p>
 * summary:
 * AES symmetric encryption, encryption and decryption compared with or encryption is still a bit complex, security is also higher than or encryption, AES encryption is not absolute security.
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
     * AES secret key key must be 16 bits.
     */
    private final static String AES_KEY = "xjp_12345!^-=42#";


    /**
     * AES 加密
     *
     * @param source Encrypted file path
     * @param dest   加密后的文件路径
     */
    public static void encryptByAES(String source, String dest) {
        encryptByAES(MODE_ENCRYPTION, source, dest);
    }

    /**
     * AES 解密
     *
     * @param source File path to be decrypted
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
