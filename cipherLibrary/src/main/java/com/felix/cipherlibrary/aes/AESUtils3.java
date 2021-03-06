package com.felix.cipherlibrary.aes;

import java.io.UnsupportedEncodingException;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

/**
 * Created by Felix.Zhong on 2018/8/22 14:56
 */
public class AESUtils3 {
    /**
     * 算法/模式/填充
     */
    private static final String CIPHER_MODE = "AES/ECB/PKCS5Padding";

    /**
     * 创建密钥
     */
    private static SecretKeySpec createKey(String password) {
        byte[] data = null;
        if (password == null) {
            password = "";
        }
        StringBuilder sb = new StringBuilder(32);
        sb.append(password);
        while (sb.length() < 32) {
            sb.append("0");
        }
        if (sb.length() > 32) {
            sb.setLength(32);
        }

        try {
            data = sb.toString().getBytes("UTF-8");
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        return new SecretKeySpec(data, "AES");
    }

    /**
     * 加密字节数据
     *
     * @param content  content
     * @param password password
     * @return byte[]
     */
    public static byte[] encrypt(byte[] content, String password) {
        try {
            SecretKeySpec key = createKey(password);
            System.out.println(key);
            Cipher cipher = Cipher.getInstance(CIPHER_MODE);
            cipher.init(Cipher.ENCRYPT_MODE, key);
            return cipher.doFinal(content);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * Encryption (result is 16 binary string)
     *
     * @param content  content
     * @param password password
     * @return String
     */
    public static String encrypt(String content, String password) {
        byte[] data = null;
        try {
            data = content.getBytes("UTF-8");
        } catch (Exception e) {
            e.printStackTrace();
        }
        data = encrypt(data, password);
        assert data != null;
        return byte2hex(data);
    }

    /**
     * 解密字节数组
     */
    private static byte[] decrypt(byte[] content, String password) {
        try {
            SecretKeySpec key = createKey(password);
            Cipher cipher = Cipher.getInstance(CIPHER_MODE);
            cipher.init(Cipher.DECRYPT_MODE, key);
            return cipher.doFinal(content);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * 解密16进制的字符串为字符串
     *
     * @param content  content
     * @param password password
     * @return String
     */
    public static String decrypt(String content, String password) {
        byte[] data = null;
        try {
            data = hex2byte(content);
        } catch (Exception e) {
            e.printStackTrace();
        }
        data = decrypt(data, password);
        if (data == null) {
            return null;
        }
        String result = null;
        try {
            result = new String(data, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        return result;
    }

    /**
     * Byte array to 16 binary string
     */
    private static String byte2hex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        String tmp;
        for (byte aB : b) {
            // 整数转成十六进制表示
            tmp = (Integer.toHexString(aB & 0XFF));
            if (tmp.length() == 1) {
                sb.append("0");
            }
            sb.append(tmp);
        }
        // 转成大写
        return sb.toString().toUpperCase();
    }

    /**
     * 将hex字符串转换成字节数组
     */
    private static byte[] hex2byte(String inputString) {
        if (inputString == null || inputString.length() < 2) {
            return new byte[0];
        }
        inputString = inputString.toLowerCase();
        int l = inputString.length() / 2;
        byte[] result = new byte[l];
        for (int i = 0; i < l; ++i) {
            String tmp = inputString.substring(2 * i, 2 * i + 2);
            result[i] = (byte) (Integer.parseInt(tmp, 16) & 0xFF);
        }
        return result;
    }
}
