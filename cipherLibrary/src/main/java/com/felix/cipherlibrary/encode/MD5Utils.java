package com.felix.cipherlibrary.encode;


import com.felix.cipherlibrary.Salt;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.DigestInputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Created by Felix.Zhong on 2018/8/22 11:52
 * MD5加密工具类
 */
public class MD5Utils {

    public static void main(String[] args) {
        System.out.println(getMD5Code("abc"));
        System.out.println(md5("abc"));
    }

    private static final String DEFAULT_ENCODING = "UTF-8";

    /**
     * 使用MD5算法加密字符串
     *
     * @param info 需要加密的字符串
     * @return 加密后的字符串
     */
    public static String getMD5CodeWithSaltPassword(String info) {
        return getMD5Code(info + Salt.SALT_PASSWORD.getSalt());
    }

    /**
     * 使用MD5算法加密字符串
     *
     * @param info 需要加密的字符串
     * @return 加密后的字符串
     */
    public static String getMD5Code(String info) {
        String md5Code = "";
        try {
            MessageDigest md5 = MessageDigest.getInstance("MD5");
            md5.update(info.getBytes(DEFAULT_ENCODING));
            byte[] encryption = md5.digest();
            StringBuilder stringBuffer = new StringBuilder();
            for (byte anEncryption : encryption) {
                String hexString = Integer.toHexString(0xff & anEncryption);
                if (hexString.length() == 1) {
                    stringBuffer.append("0");
                }
                stringBuffer.append(hexString);
            }
            md5Code = stringBuffer.toString();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return md5Code;
    }

    /**
     * 服务器端md5算法
     *
     * @param content 需要加密的原文
     * @return 加密后的密文
     */
    public static String md5(String content) {
        MessageDigest md5;
        StringBuilder hexValue;
        try {
            md5 = MessageDigest.getInstance("MD5");
            byte[] byteArray = content.getBytes("UTF-8");
            byte[] md5Bytes = md5.digest(byteArray);
            hexValue = new StringBuilder();
            for (byte md5Byte : md5Bytes) {
                int val = ((int) md5Byte) & 0xff;
                if (val < 16) {
                    hexValue.append("0");
                }
                hexValue.append(Integer.toHexString(val));
            }
        } catch (Exception e) {
            System.out.println(e.toString());
            e.printStackTrace();
            return "";
        }
        return hexValue.toString();
    }


    /**
     * 使用MD5算法加密文件
     *
     * @param file 需要加密的文件
     * @return 加密后的文件
     */
    public static String md5ForFile(File file) {
        int bufferSize = 1024;
        FileInputStream fis;
        DigestInputStream dis;
        try {
            //创建MD5转换器和文件流
            MessageDigest messageDigest = MessageDigest.getInstance("MD5");
            fis = new FileInputStream(file);
            dis = new DigestInputStream(fis, messageDigest);

            byte[] buffer = new byte[bufferSize];
            //DigestInputStream实际上在流处理文件时就在内部就进行了一定的处理
            while (dis.read(buffer) > 0) {
            }

            //通过DigestInputStream对象得到一个最终的MessageDigest对象。
            messageDigest = dis.getMessageDigest();

            // 通过messageDigest拿到结果，也是字节数组，包含16个元素
            byte[] array = messageDigest.digest();
            // 同样，把字节数组转换成字符串
            StringBuilder hex = new StringBuilder(array.length * 2);
            for (byte b : array) {
                if ((b & 0xFF) < 0x10) {
                    hex.append("0");
                }
                hex.append(Integer.toHexString(b & 0xFF));
            }
            return hex.toString();
        } catch (NoSuchAlgorithmException | IOException e) {
            e.printStackTrace();
        }

        return null;
    }
}
