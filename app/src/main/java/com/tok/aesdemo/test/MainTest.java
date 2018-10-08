package com.tok.aesdemo.test;

import com.tok.aesdemo.rsa.RSAUtils;

import java.security.KeyPair;

/**
 * Created by Felix.Zhong on 2018/10/7 11:48
 * 测试类
 */
public class MainTest {

    public static void main(String[] args) {
        byte[] srcData = "123456".getBytes();

        KeyPair keyPair = RSAUtils.generateRSAKeyPair(511);
        String cryptData = RSAUtils.encryptDataByPublicKey(srcData, keyPair.getPublic());
        System.out.println("加密后 cryptData = " + cryptData);

        String decryptData = RSAUtils.decryptToStrByPrivate(cryptData, keyPair.getPrivate());
        System.out.println("解密后 decryptData = " + decryptData);
    }
}
