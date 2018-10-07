package com.tok.aesdemo;

import android.text.TextUtils;
import android.util.Base64;
import android.util.Log;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Created by Felix.Zhong on 2018/9/30 15:51
 */
public class AESUtils2 {
    private static final String TAG = "AESUtils";

    // CBC(Cipher Block Chaining, 加密快链)模式，PKCS7Padding补码方式
    // AES是加密方式 CBC是工作模式 PKCS5Padding是填充模式
    private static final String CBC_PKCS5_PADDING = "AES/CBC/PKCS5Padding";
    // AES 加密
    private static final String AES = "AES";
    // 密钥偏移量
    private static final String mstrIvParameter = "1234567890123456";
    /* key必须为16位，可更改为自己的key */
    //String mstrTestKey = "1234567890123456";

    // 加密
    public static String encrypt(String strKey, String strClearText) throws Exception {
        // //Log.d(TAG, "### begin encrypt: ");
        // //Log.d(TAG, "key = " + strKey + ",ClearText: " + strClearText);

        /*if (TextUtils.isEmpty(strClearText)) {
            // //Log.e(TAG, "clear text is empty.");
            return null;
        }*/

        if (null == strKey) {
           // //Log.e(TAG, "encrypt KEY is null.");
            return null;
        }

        // check the KEY is 16 or not
        /*if (16 != strKey.length()) {
             // //Log.e(TAG, "encrypt KEY length is 16.");
            return null;
        }*/

        try {
            byte[] raw = strKey.getBytes();
            SecretKeySpec skeySpec = new SecretKeySpec(raw, AES);

            Cipher cipher = Cipher.getInstance(CBC_PKCS5_PADDING);
            IvParameterSpec iv = new IvParameterSpec(mstrIvParameter.getBytes());
            cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);

            byte[] cipherText = cipher.doFinal(strClearText.getBytes());
             //Log.d(TAG, "encrypt result(not BASE64): " + cipherText.toString());
            String strBase64Content = Base64.encodeToString(cipherText, Base64.DEFAULT); // encode it by BASE64 again
             //Log.d(TAG, "encrypt result(BASE64): " + strBase64Content);

            return strBase64Content;
        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }

    // 解密
    public static String decrypt(String strKey, String strCipherText) throws Exception {
         // //Log.d(TAG, "### begin decrypt: ");
         //Log.d(TAG, "key = " + strKey + ",CipherText: " + strCipherText);

        /*if (TextUtils.isEmpty(strCipherText)) {
             // //Log.e(TAG, "cipher text is empty.");
            return null;
        }*/

        if (null == strKey) {
             //Log.e(TAG, "decrypt KEY is null.");
            return null;
        }

        // check the KEY is 16 or not
        if (16 != strKey.length()) {
             //Log.e(TAG, "decrypt KEY length is 16.");
            return null;
        }

        try {
            byte[] raw = strKey.getBytes("ASCII");
            SecretKeySpec skeySpec = new SecretKeySpec(raw, AES);

            Cipher cipher = Cipher.getInstance(CBC_PKCS5_PADDING);
            IvParameterSpec iv = new IvParameterSpec(mstrIvParameter.getBytes());
            cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);

            byte[] cipherText = Base64.decode(strCipherText, Base64.DEFAULT); // decode by BASE64 first
             //Log.d(TAG, "BASE64 decode result(): " + cipherText.toString());
            byte[] clearText = cipher.doFinal(cipherText);
            String strClearText = new String(clearText);
             //Log.d(TAG, "decrypt result: " + strClearText);

            return strClearText;
        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }



    public static final String PUBLIC_KEY_STR = "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAILho76AqLkeilrjmOUCKhXQAe9Ul4QzfiS/y0HXmdx64mPtvukXi++dJGTWuIMxwlXR4+0ynb1yPRX+hV10yAkCAwEAAQ==";

    public static void main(String[] args) {
        String content = PUBLIC_KEY_STR;
        String password = "da09a9528b9c710addd8439684e09608";
        //加密
        System.out.println("加密前：" + content);
        String encryptResultStr = null;
        try {
            encryptResultStr = encrypt(password,content);
        } catch (Exception e) {
            e.printStackTrace();
        }
        System.out.println("加密后：" + encryptResultStr);
        //解密
        String decryptResult = null;
        try {
            decryptResult = decrypt(password,encryptResultStr);
        } catch (Exception e) {
            e.printStackTrace();
        }
        System.out.println("解密后：" + decryptResult);
    }
}
