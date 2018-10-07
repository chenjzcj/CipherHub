package com.tokok.tok.api.safe.encrypt;

import android.text.TextUtils;

import com.blankj.utilcode.util.LogUtils;

import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * AES加密解密工具类
 *
 * @author M-Y
 */
public class AESUtil_1 {
    /**
     * 编码格式
     */
    private static final String defaultCharset = "UTF-8";
    /**
     * 加密算法AES
     */
    private static final String KEY_AES = "AES";
    /**
     * 私钥key
     */
    private static final String KEY = "c785ed46444693d2da804189b4420cc6";
    /**
     * AES/ECB/PKCS5Padding 算法加解密
     */
    private static final String KEY_MODEL = "AES/ECB/NoPadding";
    //private static final String KEY_MODEL = "AES/CBC/PKCS5PADDING";
    /**
     * 签名算法
     */
    public static final String SIGNATURE_ALGORITHM = "SHA1PRNG";


    /**
     * 加密
     *
     * @param data 需要加密的内容
     * @param key  加密密码
     * @return
     */
    public static String encrypt(String data, String key) {
        return doAES(data, key, Cipher.ENCRYPT_MODE);
    }

    /**
     * 解密
     *
     * @param data 待解密内容
     * @param key  解密密钥
     * @return
     */
    public static String decrypt(String data, String key) {
        return doAES(data, key, Cipher.DECRYPT_MODE);
    }

    /**
     * 加解密
     *
     * @param data 待处理数据
     * @param mode 加解密mode
     * @return
     */
    private static String doAES(String data, String key, int mode) {
        //判断是加密还是解密
        boolean encrypt = mode == Cipher.ENCRYPT_MODE;

        String s = encrypt ? "加密" : "解密";
        LogUtils.i("aaaaaaaaaaaaaa " + s + "data =" + data+ "key =" + key);
        try {
            if (TextUtils.isEmpty(data) || TextUtils.isEmpty(key)) {
                return null;
            }

            byte[] content;
            //true 加密内容 false 解密内容
            if (encrypt) {
                content = data.getBytes(defaultCharset);
            } else {
                content = parseHexStr2Byte(data);
            }
            //1.构造密钥生成器，指定为AES算法,不区分大小写
            KeyGenerator kgen = KeyGenerator.getInstance(KEY_AES);
            //2.根据ecnodeRules规则初始化密钥生成器
            //生成一个128位的随机源,根据传入的字节数组

            SecureRandom random = SecureRandom.getInstance("SHA1PRNG", "Crypto");
            random.setSeed(key.getBytes());
            kgen.init(128, random);
            //3.产生原始对称密钥
            SecretKey secretKey = kgen.generateKey();
            //4.获得原始对称密钥的字节数组
            byte[] enCodeFormat = secretKey.getEncoded();
            //5.根据字节数组生成AES密钥
            SecretKeySpec keySpec = new SecretKeySpec(enCodeFormat, KEY_MODEL);
            //6.根据指定算法AES自成密码器
            Cipher cipher = Cipher.getInstance(KEY_MODEL);// 创建密码器
            //7.初始化密码器，第一个参数为加密(Encrypt_mode)或者解密解密(Decrypt_mode)操作，第二个参数为使用的KEY
            cipher.init(mode, keySpec);// 初始化
            byte[] result = cipher.doFinal(content);
            if (encrypt) {
                //将二进制转换成16进制
                return parseByte2HexStr(result);
            } else {
                LogUtils.i("aaaaaaaaaaaaaa " + s + "result =  " + Arrays.toString(result));
                LogUtils.i("aaaaaaaaaaaaaa " + s + "result2 =  " + new String(result, defaultCharset));
                return new String(result, defaultCharset);
            }
        } catch (Exception e) {
            LogUtils.e("AES 密文处理异常", e);
        }
        return null;
    }

    /**
     * 将二进制转换成16进制
     *
     * @param buf
     * @return
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
     * 将16进制转换为二进制
     *
     * @param hexStr
     * @return
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

    public static String md5(String content, String algorithm) throws Exception {
        MessageDigest md5 = null;
        try {
            md5 = MessageDigest.getInstance(algorithm);
        } catch (Exception e) {
            LogUtils.e("md5出错：", e);
            return "";
        }
        byte[] byteArray = content.getBytes(defaultCharset);
        byte[] md5Bytes = md5.digest(byteArray);
        StringBuffer hexValue = new StringBuffer();
        for (int i = 0; i < md5Bytes.length; i++) {
            int val = ((int) md5Bytes[i]) & 0xff;
            if (val < 16) {
                hexValue.append("0");
            }
            hexValue.append(Integer.toHexString(val));
        }
        return hexValue.toString();
    }

    public static void main(String[] args) throws Exception {
        String content = "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAILho76AqLkeilrjmOUCKhXQAe9Ul4QzfiS/y0HXmdx64mPtvukXi++dJGTWuIMxwlXR4+0ynb1yPRX+hV10yAkCAwEAAQ==";
        System.out.println("加密前：" + content);
        System.out.println("加密密钥和解密密钥：" + KEY);
        String encrypt = encrypt(content, KEY);
        System.out.println("加密后：" + encrypt);
        String decrypt = decrypt("D32C60E26D934401FDF144BBADBA8A287008CCD30884651AB0446B80913CBE349C7997B26FCDAA428E4F936A8E6289D3627ED45EA329D80A720ECD6DECEFBED1B70CFF70B24469FCD9E18C53C5B96A805FDB90E76D5318BC2C9CE722E5EE567C24725C4A319A4841F5BC13D68CC2736D0D6B5E939250A6278022872CA4230FA5", KEY);
        System.out.println("解密后：" + decrypt);
       /*  byte[] buf = {-51, 22, -54, -122, 80, 113, -65, 41, -85, -60, -95, -11, -93, 107, 14, -124, 51, 10, -80, 41, -41, 41, -59, 85, 41, -54, 14, -8, 78, -73, -8, -111, -108, -52, -1, 66, -48, -14, 36, 11, -80, 55, -110, 98, -115, -88, -8, 127, 82, 112, 4, -121, -122, -34, 49, 24, -102, 72, 20, -87, 30, 74, -77, 74, 93, -34, 127, 59, 90, -25, 106, -63, -47, 26, -15, -27, 8, 79, 5, 57, 121, -45, -51, -106, 35, -1, 101, 75, -85, -54, -4, 104, -128, 118, 28, -119, -59, 29, -99, -82, 105, -48, -120, 16, 65, 29, -83, 48, -63, 101, -116, -53, -118, -40, -22, -7, 40, 33, -2, -34, -91, 101, -94, -36, -10, -1, 35, 31};
		String parseByte2HexStr = parseByte2HexStr(buf );
		 System.out.println("parseByte2HexStr：" + parseByte2HexStr); */
    }

}

