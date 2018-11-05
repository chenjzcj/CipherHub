package com.felix.cipherlibrary.aes;

import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * In the Java environment, encryption and decryption can be normal, but in Android environment, encryption and decryption problems (each encrypted string is different)
 * <p>
 * {AES128 算法，加密模式为ECB，填充模式为 pkcs7（实际就是pkcs5）}
 */
public class AESUtils {
    /**
     * 加密
     *
     * @param content Content that needs encryption
     * @param key     加密密码
     * @return Byte array after encryption
     */
    public static byte[] encrypt(String content, String key) {
        try {
            String type = "AES";
            KeyGenerator kgen = KeyGenerator.getInstance(type);
            // Prevent random generation of key under Linux
            SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG");
            secureRandom.setSeed(key.getBytes());
            //还可以这样初始化：kgen.init(128, new SecureRandom(password.getBytes()));
            kgen.init(128, secureRandom);
            SecretKey secretKey = kgen.generateKey();
            byte[] enCodeFormat = secretKey.getEncoded();
            SecretKeySpec secretKeySpec = new SecretKeySpec(enCodeFormat, type);
            // Create a cipher
            Cipher cipher = Cipher.getInstance(type);
            byte[] byteContent = content.getBytes("UTF-8");
            // Initialization
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
            byte[] result = cipher.doFinal(byteContent);
            //System.out.println("result = " + Arrays.toString(result));
            // 加密
            return result;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * 解密
     *
     * @param content Contents to be declassified
     * @param key     解密密钥
     * @return Byte array after decryption
     */
    public static byte[] decrypt(byte[] content, String key) {
        try {
            String type = "AES";
            KeyGenerator kgen = KeyGenerator.getInstance(type);
            // Prevent random generation of key under Linux
            SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG");
            secureRandom.setSeed(key.getBytes());
            //还可以这样初始化：kgen.init(128, new SecureRandom(password.getBytes()));
            kgen.init(128, secureRandom);
            SecretKey secretKey = kgen.generateKey();
            byte[] enCodeFormat = secretKey.getEncoded();
            SecretKeySpec secretKeySpec = new SecretKeySpec(enCodeFormat, type);
            // Create a cipher
            Cipher cipher = Cipher.getInstance(type);
            // Initialization
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);
            byte[] result = cipher.doFinal(content);
            //System.out.println("result = " + Arrays.toString(result));
            // 解密
            return result;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * String encryption, returns the encrypted string.
     *
     * @param content String to be encrypted
     * @param key     加密的AES Key
     * @return Encrypted string
     */
    public static String encryptString(String content, String key) {
        byte[] encrypt = encrypt(content, key);
        if (encrypt == null) {
            return "";
        }
        return parseByte2HexStr(encrypt);
    }

    /**
     * String decryption, return the string after the decryption.
     *
     * @param content String to decrypt
     * @param key     解密的AES Key
     * @return Decrypted string
     */
    public static String decryptString(String content, String key) {
        byte[] decryptFrom = parseHexStr2Byte(content);
        byte[] decryptResult = decrypt(decryptFrom, key);
        if (decryptResult == null) {
            return "";
        }
        return new String(decryptResult);
    }

    /**
     * Convert binary to 16 hexadecimal, and turn it all into capital letters.
     *
     * @param buf An array of bytes that need to be converted into 16 binary strings.
     * @return Converted to 16 hexadecimal strings
     */
    public static String parseByte2HexStr(byte[] buf) {
        StringBuilder sb = new StringBuilder();
        for (byte b : buf) {
            String hex = Integer.toHexString(b & 0xFF);
            if (hex.length() == 1) {
                hex = '0' + hex;
            }
            sb.append(hex.toUpperCase());
        }
        return sb.toString();
    }

    /**
     * Converting 16 binary to binary
     *
     * @param hexStr 16 hexadecimal string
     * @return 转换后的字节数组
     */
    public static byte[] parseHexStr2Byte(String hexStr) {
        int length = hexStr.length();
        if (length < 1) {
            return null;
        }
        byte[] result = new byte[length / 2];
        for (int i = 0; i < result.length; i++) {
            int high = Integer.parseInt(hexStr.substring(i * 2, i * 2 + 1), 16);
            int low = Integer.parseInt(hexStr.substring(i * 2 + 1, i * 2 + 2), 16);
            result[i] = (byte) (high * 16 + low);
        }
        return result;
    }

    public static void main(String[] args) {
        String content = "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAILho76AqLkeilrjmOUCKhXQAe9Ul4QzfiS/y0HXmdx64mPtvukXi++dJGTWuIMxwlXR4+0ynb1yPRX+hV10yAkCAwEAAQ==";
        String password = "da09a9528b9c710addd8439684e09608";

        //加密
        System.out.println("加密前：" + content);
        byte[] encryptResult = encrypt(content, password);
        String encryptResultStr = parseByte2HexStr(encryptResult);
        System.out.println("加密后：" + encryptResultStr);

        //解密
        byte[] decryptFrom = parseHexStr2Byte(encryptResultStr);
        byte[] decryptResult = decrypt(decryptFrom, password);
        System.out.println("解密后：" + new String(decryptResult));

        password = "25d55ad283aa400af464c76d713c07ad";

        //加密
        String encrypt = encryptString(content, password);
        System.out.println("加密后：" + encrypt);
        //解密
        String decrypt = decryptString(encrypt, password);
        System.out.println("解密后：" + decrypt);
    }
}
