/**
 * Copyright:   北京互融时代软件有限公司
 *
 * @author: Liu Shilei
 * @version: V1.0
 * @Date: 2016年5月24日 下午7:43:01
 */
package com.tok.aesdemo;

import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.IvParameterSpec;

/**
 * <p>
 * 加密解密>
 *
 * @author: Liu Shilei
 * @Date : 2016年5月24日 下午7:43:01
 */
public class SecurityEncode {

    public static final String ALGORITHM_DES = "DES/CBC/PKCS5Padding";

    public static final String PUBLICE_KEY = "HURONGYUN";

    /**
     * 加密
     * <p> TODO</p>
     *
     * @author: Liu Shilei
     * @param: @param data
     * @param: @return
     * @return: String
     * @Date :          2016年5月25日 上午9:48:29
     * @throws:
     */
    public static String encodeStr(String data) {
        return encode(PUBLICE_KEY, data);
    }

    /**
     * 解密
     * <p> TODO</p>
     *
     * @author: Liu Shilei
     * @param: @param data
     * @param: @return
     * @return: String
     * @Date :          2016年5月25日 上午9:49:14
     * @throws:
     */
    public static String decodeStr(String data) {
        return decode(PUBLICE_KEY, data);
    }


    /**
     * DES算法，加密
     *
     * @param data 待加密字符串
     * @param key  加密私钥，长度不能够小于8位
     * @return 加密后的字节数组，一般结合Base64编码使用
     * @throws InvalidAlgorithmParameterException
     * @throws Exception
     */
    public static String encode(String key, String data) {
        if (data == null)
            return null;
        try {
            DESKeySpec dks = new DESKeySpec(key.getBytes());
            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DES");
            // key的长度不能够小于8位字节
            Key secretKey = keyFactory.generateSecret(dks);
            Cipher cipher = Cipher.getInstance(ALGORITHM_DES);
            IvParameterSpec iv = new IvParameterSpec("12345678".getBytes());
            AlgorithmParameterSpec paramSpec = iv;
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, paramSpec);
            byte[] bytes = cipher.doFinal(data.getBytes());
            return byte2hex(bytes);
        } catch (Exception e) {
            e.printStackTrace();
            return data;
        }
    }

    /**
     * DES算法，解密
     *
     * @param data 待解密字符串
     * @param key  解密私钥，长度不能够小于8位
     * @return 解密后的字节数组
     * @throws Exception 异常
     */
    public static String decode(String key, String data) {
        if (data == null)
            return null;
        try {
            DESKeySpec dks = new DESKeySpec(key.getBytes());
            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DES");
            // key的长度不能够小于8位字节
            Key secretKey = keyFactory.generateSecret(dks);
            Cipher cipher = Cipher.getInstance(ALGORITHM_DES);
            IvParameterSpec iv = new IvParameterSpec("12345678".getBytes());
            AlgorithmParameterSpec paramSpec = iv;
            cipher.init(Cipher.DECRYPT_MODE, secretKey, paramSpec);
            return new String(cipher.doFinal(hex2byte(data.getBytes())));
        } catch (Exception e) {
            e.printStackTrace();
            return data;
        }
    }

    /**
     * 二行制转字符串
     *
     * @param b
     * @return
     */
    private static String byte2hex(byte[] b) {
        StringBuilder hs = new StringBuilder();
        String stmp;
        for (int n = 0; b != null && n < b.length; n++) {
            stmp = Integer.toHexString(b[n] & 0XFF);
            if (stmp.length() == 1)
                hs.append('0');
            hs.append(stmp);
        }
        return hs.toString().toUpperCase();
    }

    private static byte[] hex2byte(byte[] b) {
        if ((b.length % 2) != 0)
            throw new IllegalArgumentException();
        byte[] b2 = new byte[b.length / 2];
        for (int n = 0; n < b.length; n += 2) {
            String item = new String(b, n, 2);
            b2[n / 2] = (byte) Integer.parseInt(item, 16);
        }
        return b2;
    }

    /**
     * 使用指定key加密
     * <p> TODO</p>
     *
     * @author: Shangxl
     * @param: @param key
     * @param: @param data
     * @param: @return
     * @return: String
     * @Date :          2017年7月26日 上午11:18:05
     * @throws:
     */
    public static String encodeByKey(String key, String data) {
        if (data == null)
            return null;
        try {
            DESKeySpec dks = new DESKeySpec(key.getBytes());
            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DES");
            // key的长度不能够小于8位字节
            Key secretKey = keyFactory.generateSecret(dks);
            Cipher cipher = Cipher.getInstance(ALGORITHM_DES);
            IvParameterSpec iv = new IvParameterSpec("12345678".getBytes());
            AlgorithmParameterSpec paramSpec = iv;
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, paramSpec);
            byte[] bytes = cipher.doFinal(data.getBytes());
            return byte2hex(bytes);
        } catch (Exception e) {
            e.printStackTrace();
            return data;
        }
    }


    public static void main(String[] args) {

        //final String PUBLIC_KEY_STR = "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAILho76AqLkeilrjmOUCKhXQAe9Ul4QzfiS/y0HXmdx64mPtvukXi++dJGTWuIMxwlXR4+0ynb1yPRX+hV10yAkCAwEAAQ==";
        //String encodeStr = encode("25d55ad283aa400af464c76d713c07ad",PUBLIC_KEY_STR);
        //System.out.println(encodeStr);
        System.out.println(decode("25d55ad283aa400af464c76d713c07ad", "B79F130FE34EF3248D0E464DF9EA046B3B22533C7913F27A549CC198A150B319FCCED209E332E195E6D1A84B8D21D7967D0CED5F844CD49ED3D06F90B4ED29734AFAC5C641B8B27A7F8C2482BD5593F9525F63683B8DE611BA2E69F45F17295138B89AF610184A2F695029402BC44AD3C7E43A861775E972DE846F7989867215EFE8316357B61C0B"));


    }


}
