package com.felix.cipherlibrary.aes;

import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * 在java环境可以正常加解密，但是到了安卓环境，加解密有问题(每次加密的字符串不一样)
 * <p>
 * {AES128 算法，加密模式为ECB，填充模式为 pkcs7（实际就是pkcs5）}
 */
public class AESUtils {
    /**
     * 加密
     *
     * @param content 需要加密的内容
     * @param key     加密密码
     * @return 加密后字节数组
     */
    public static byte[] encrypt(String content, String key) {
        try {
            String type = "AES";
            KeyGenerator kgen = KeyGenerator.getInstance(type);
            // 防止linux下 随机生成key
            SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG");
            secureRandom.setSeed(key.getBytes());
            //还可以这样初始化：kgen.init(128, new SecureRandom(password.getBytes()));
            kgen.init(128, secureRandom);
            SecretKey secretKey = kgen.generateKey();
            byte[] enCodeFormat = secretKey.getEncoded();
            SecretKeySpec secretKeySpec = new SecretKeySpec(enCodeFormat, type);
            // 创建密码器
            Cipher cipher = Cipher.getInstance(type);
            byte[] byteContent = content.getBytes("UTF-8");
            // 初始化
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
     * @param content 待解密内容
     * @param key     解密密钥
     * @return 解密后字节数组
     */
    public static byte[] decrypt(byte[] content, String key) {
        try {
            String type = "AES";
            KeyGenerator kgen = KeyGenerator.getInstance(type);
            // 防止linux下 随机生成key
            SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG");
            secureRandom.setSeed(key.getBytes());
            //还可以这样初始化：kgen.init(128, new SecureRandom(password.getBytes()));
            kgen.init(128, secureRandom);
            SecretKey secretKey = kgen.generateKey();
            byte[] enCodeFormat = secretKey.getEncoded();
            SecretKeySpec secretKeySpec = new SecretKeySpec(enCodeFormat, type);
            // 创建密码器
            Cipher cipher = Cipher.getInstance(type);
            // 初始化
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
     * 字符串加密,返回加密后的字符串
     *
     * @param content 要加密的字符串
     * @param key     加密的AES Key
     * @return 加密后的字符串
     */
    public static String encryptString(String content, String key) {
        byte[] encrypt = encrypt(content, key);
        if (encrypt == null) {
            return "";
        }
        return parseByte2HexStr(encrypt);
    }

    /**
     * 字符串解密，返回解密后的字符串
     *
     * @param content 要解密的字符串
     * @param key     解密的AES Key
     * @return 解密后的字符串
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
     * 将二进制转换成16进制,全部转成大写
     *
     * @param buf 需要转成16进制字符串的字节数组
     * @return 转换成16进制后的字符串
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
     * 将16进制转换为二进制
     *
     * @param hexStr 16进制字符串
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
