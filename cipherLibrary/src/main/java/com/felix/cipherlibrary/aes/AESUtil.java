package com.felix.cipherlibrary.aes;


import android.text.TextUtils;

import com.blankj.utilcode.util.LogUtils;

import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * AES encryption and decryption tools category
 *
 * @author M-Y
 * 验证不可用，报错java.lang.ExceptionInInitializerError
 */
public class AESUtil {
    private static final String defaultCharset = "UTF-8";
    private static final String KEY_AES = "AES";
    private static final String KEY = "dhjaslahlahdlahdlahdahdkahdlhasdhasdklhasldhkasdhkashdkjashdkjashdklasjhdkjahdklashflasfkldhasflkdhasfklhasdfkldasfldaslfhasdlfhdlashflasdhfdlashflasdhfdlashfldashfdjshfdkjshfdkjashfdkjashfdkjashfdkjashfdashfdljshfdasklfhd;lashfdh;lasfhdasfkjahsd;fklhdas;faswfafdasfdasfdasfdasfdasfdasfdasfdsfdasfdasfdasfdasfas";

    /**
     * 加密
     *
     * @param data Content that needs encryption
     * @param key  加密密码
     * @return String
     */
    public static String encrypt(String data, String key) {
        return doAES(data, key, Cipher.ENCRYPT_MODE);
    }

    /**
     * 解密
     *
     * @param data Contents to be declassified
     * @param key  解密密钥
     * @return String
     */
    public static String decrypt(String data, String key) {
        return doAES(data, key, Cipher.DECRYPT_MODE);
    }

    /**
     * Encryption and decryption
     *
     * @param data Data to be processed
     * @param mode 加解密mode
     * @return String
     */
    private static String doAES(String data, String key, int mode) {
        try {
            if (TextUtils.isEmpty(data) || TextUtils.isEmpty(key)) {
                return null;
            }
            //Is encryption encrypted or decrypted?
            boolean encrypt = mode == Cipher.ENCRYPT_MODE;
            byte[] content;
            //true 加密内容 false 解密内容
            if (encrypt) {
                content = data.getBytes(defaultCharset);
            } else {
                content = parseHexStr2Byte(data);
            }
            //1.Construct a key generator, designated as the AES algorithm, not case sensitive.
            KeyGenerator kgen = KeyGenerator.getInstance(KEY_AES);
            //2.根据ecnodeRules规则初始化密钥生成器
            //Generates a 128 bit random source, based on the incoming byte array.
            kgen.init(128, new SecureRandom(key.getBytes()));
            //3.产生原始对称密钥
            SecretKey secretKey = kgen.generateKey();
            //4.Gets the byte array of the original symmetric key.
            byte[] enCodeFormat = secretKey.getEncoded();
            //5.根据字节数组生成AES密钥
            SecretKeySpec keySpec = new SecretKeySpec(enCodeFormat, KEY_AES);
            //6.Generate cipher based on the specified algorithm AES
            // Create a cipher
            Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
            //7.Initialize the cipher, the first parameter is the Encrypt_mode or Decrypt_mode operation, and the second parameter is the KEY used.
            // Initialization
            cipher.init(mode, keySpec);
            byte[] result = cipher.doFinal(content);
            if (encrypt) {
                //Converting binary to 16 binary system
                return parseByte2HexStr(result);
            } else {
                LogUtils.i("result = " + Arrays.toString(result));
                return new String(result, defaultCharset);
            }
        } catch (Exception e) {
            LogUtils.e("AES 密文处理异常", e);
        }
        return null;
    }

    /**
     * Converting binary to 16 binary system
     *
     * @param buf byte
     * @return String
     */
    public static String parseByte2HexStr(byte buf[]) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < buf.length; i++) {
            String hex = Integer.toHexString(buf[i] & 0xFF);
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
     * @param hexStr String
     * @return byte[]
     */
    public static byte[] parseHexStr2Byte(String hexStr) {
        if (hexStr.length() < 1) {
            return null;
        }
        byte[] result = new byte[hexStr.length() / 2];
        for (int i = 0; i < hexStr.length() / 2; i++) {
            int high = Integer.parseInt(hexStr.substring(i * 2, i * 2 + 1), 16);
            int low = Integer.parseInt(hexStr.substring(i * 2 + 1, i * 2 + 2), 16);
            result[i] = (byte) (high * 16 + low);
        }
        return result;
    }

    public static void main(String[] args) {
        String content = "{'repairPhone':'18547854787','customPhone':'12365478965','captchav':'58m7'}";
        System.out.println("加密前：" + content);
        System.out.println("加密密钥和解密密钥：" + KEY);
        String encrypt = encrypt(content, KEY);
        System.out.println("加密后：" + encrypt);
        String decrypt = decrypt(encrypt, KEY);
        System.out.println("解密后：" + decrypt);
    }
}

