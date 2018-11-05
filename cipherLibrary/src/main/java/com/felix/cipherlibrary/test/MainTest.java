package com.felix.cipherlibrary.test;

import com.felix.cipherlibrary.rsa.RSAUtils;

import java.security.KeyPair;

/**
 * Created by Felix.Zhong on 2018/10/7 11:48
 * test class
 */
public class MainTest {

    public static void main(String[] args) {
        byte[] srcData = "123456".getBytes();

        KeyPair keyPair = RSAUtils.generateRSAKeyPair(511);
        String cryptData = RSAUtils.encryptDataByPublicKey(srcData, keyPair.getPublic());
        System.out.println("after encode cryptData = " + cryptData);

        String decryptData = RSAUtils.decryptToStrByPrivate(cryptData, keyPair.getPrivate());
        System.out.println("after decode decryptData = " + decryptData);
    }
}
