package com.tokok.tok.api.safe.encrypt;

import com.scottyab.aescrypt.AESCrypt;

import java.security.GeneralSecurityException;

/**
 * Created by Felix.Zhong on 2018/9/30 15:16
 */
public class AESTest {

    public static final String PUBLIC_KEY_STR = "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAILho76AqLkeilrjmOUCKhXQAe9Ul4QzfiS/y0HXmdx64mPtvukXi++dJGTWuIMxwlXR4+0ynb1yPRX+hV10yAkCAwEAAQ==";

    public static void main(String[] args) {
        String content = PUBLIC_KEY_STR;
        String password = "da09a9528b9c710addd8439684e09608";
        //加密
        System.out.println("加密前：" + content);
        String encryptResultStr = null;
        try {
            encryptResultStr = AESCrypt.encrypt(password,content);
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
        }
        System.out.println("加密后：" + encryptResultStr);
        //解密
        String decryptResult = null;
        try {
            decryptResult = AESCrypt.decrypt(password,encryptResultStr);
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
        }
        System.out.println("解密后：" + new String(decryptResult));
    }
}
