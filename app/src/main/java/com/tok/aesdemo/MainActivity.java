package com.tok.aesdemo;

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;
import android.view.View;

import com.tozny.crypto.android.AesCbcWithIntegrity;

import java.security.GeneralSecurityException;

public class MainActivity extends Activity {

    private AESCrypt mAESCrypt;

    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        findViewById(R.id.button).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                //aes();
                //aes2();
                aes3();
            }
        });

        mAESCrypt = new AESCrypt();
        String masterPassword = "ae2d";
        String originalText = "012测试abc";
        try {
            Log.i("dddddddddddddddd", "加密文本为" + originalText);
            String encryptingCode = mAESCrypt.encrypt(masterPassword, originalText);
            Log.i("dddddddddddddddd", "加密结果为 " + encryptingCode);
            String decryptingCode = mAESCrypt.decrypt(masterPassword, encryptingCode);
            Log.i("dddddddddddddddd", "解密结果为 " + decryptingCode);
        } catch (Exception e) {
            Log.i("dddddddddddddddd", "e " + e);
            e.printStackTrace();
        }
    }

    private void aes() {
        final String PUBLIC_KEY_STR = "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAILho76AqLkeilrjmOUCKhXQAe9Ul4QzfiS/y0HXmdx64mPtvukXi++dJGTWuIMxwlXR4+0ynb1yPRX+hV10yAkCAwEAAQ==";

        String content = PUBLIC_KEY_STR;
        String password = "da09a9528b9c710addd8439684e09608";
        //加密
        System.out.println("加密前：" + content);
        String encryptResultStr = null;
        try {
            encryptResultStr = cryptogram.encrypt(content, password);
        } catch (Exception e) {
            e.printStackTrace();
        }
        System.out.println("加密后：" + encryptResultStr);
        //解密
        String decryptResult = null;
        try {
            decryptResult = cryptogram.decrypt(encryptResultStr, password);
        } catch (Exception e) {
            e.printStackTrace();
        }
        System.out.println("解密后：" + decryptResult);

    }

    private void aes3(){
        Log.i("aaaaaaaa", (SecurityEncode.decode("25d55ad283aa400af464c76d713c07ad","B79F130FE34EF3248D0E464DF9EA046B3B22533C7913F27A549CC198A150B319FCCED209E332E195E6D1A84B8D21D7967D0CED5F844CD49ED3D06F90B4ED29734AFAC5C641B8B27A7F8C2482BD5593F9525F63683B8DE611BA2E69F45F17295138B89AF610184A2F695029402BC44AD3C7E43A861775E972DE846F7989867215EFE8316357B61C0B")));

    }

    public static void aes2() {
        /*String password = "password";
        String message = "hello world";
        AESCrypt aesCrypt = new AESCrypt();
        Log.i("aaaaaaaa", "加密前：" + message);
        String encryptedMsg = null;
        try {
            encryptedMsg = aesCrypt.encrypt(password, message);
        } catch (Exception e) {
            e.printStackTrace();
        }
        Log.i("aaaaaaaa", "加密后：" + encryptedMsg);
        //String encryptedMsg = "2B22cS3UC5s35WBihLBo8w==";

        try {
            String messageAfterDecrypt = aesCrypt.decrypt(password, encryptedMsg);
            Log.i("aaaaaaaa", "解密后：" + messageAfterDecrypt);
        } catch (Exception e) {
            e.printStackTrace();
        }*/

        final String PUBLIC_KEY_STR = "CB8B8251860F0C1F14E670323207867BE6083729CB1E24FD58FD950912524B46E2FB4B4D5E1401ABB05A6606EB9BE0E6C6BE90B84FCA7DC777493F9F4E5B1FF24C77675D1F5981B65E5190A6C79D8CE6F4384398B572AF80AA9DF92B792B530DEB4EEAB50AE5DCCF77B0D18ED12BFEDBFE696542D72202B57A3E95ECBCFC6CA880034144DA074323947D1C489A76826E";

        String content = PUBLIC_KEY_STR;
        String password = "208139976011a2bb877a785004478376";

        AesCbcWithIntegrity.SecretKeys keys;
        try {
            keys = AesCbcWithIntegrity.generateKeyFromPassword(password,"eee");
            /*Log.i("aaaaaaaa", "加密前：" + content);
            AesCbcWithIntegrity.CipherTextIvMac cipherTextIvMac = AesCbcWithIntegrity.encrypt(content, keys);
            //store or send to server
            String ciphertextString = cipherTextIvMac.toString();
            Log.i("aaaaaaaa", "加密后：" + ciphertextString);*/
            //Use the constructor to re-create the CipherTextIvMac class from the string:
            AesCbcWithIntegrity.CipherTextIvMac cipherTextIvMac2 = new AesCbcWithIntegrity.CipherTextIvMac(content);
            String plainText = AesCbcWithIntegrity.decryptString(cipherTextIvMac2, keys);
            Log.i("aaaaaaaa", "解密后：" + plainText);
        } catch (Exception e) {
            e.printStackTrace();
        }

    }
    public static void main(String[] args) {
        aes2();
    }

}
