package com.tok.aesdemo.aes;

import android.util.Log;

import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class AESCrypt {
	private final static String HEX = "0123456789ABCDEF";
	 
    public String encrypt(String seed, String cleartext) throws Exception {
        byte[] rawKey = getRawKey(seed.getBytes());
        byte[] result = encrypt(rawKey, cleartext.getBytes());
        return toHex(result);
    }
 
    public String decrypt(String seed, String encrypted) throws Exception {
        byte[] rawKey = getRawKey(seed.getBytes());
        byte[] enc = toByte(encrypted);
        byte[] result = decrypt(rawKey, enc);
        return new String(result);
    }
 
    private byte[] toByte(String hexString) {
        int len = hexString.length() / 2;
        byte[] result = new byte[len];
        for (int i = 0; i < len; i++)
            result[i] = Integer.valueOf(hexString.substring(2 * i, 2 * i + 2), 16).byteValue();
        return result;
    }
 
    private byte[] getRawKey(byte[] seed) throws Exception {     
        KeyGenerator kgen = KeyGenerator.getInstance("AES");   
        // SHA1PRNG 强随机种子算法, 要区别4.2以上版本的调用方法  
         SecureRandom sr = null;  
       if (android.os.Build.VERSION.SDK_INT >=  17) {  
         sr = SecureRandom.getInstance("SHA1PRNG", "Crypto");  
       } else {  
         sr = SecureRandom.getInstance("SHA1PRNG");  
       }   
        sr.setSeed(seed);     
        kgen.init(256, sr); //256 bits or 128 bits,192bits  
        SecretKey skey = kgen.generateKey();     
        byte[] raw = skey.getEncoded();     
        return raw;     
    } 
 
    private byte[] encrypt(byte[] raw, byte[] clear) throws Exception {
        SecretKeySpec skeySpec = new SecretKeySpec(raw, "AES");
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, skeySpec);
        byte[] encrypted = cipher.doFinal(clear);
        return encrypted;
    }
 
    private byte[] decrypt(byte[] raw, byte[] encrypted) throws Exception {
        SecretKeySpec skeySpec = new SecretKeySpec(raw, "AES");
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, skeySpec);
        byte[] decrypted = cipher.doFinal(encrypted);
        return decrypted;
    }
 
    private String toHex(String txt) {
        return toHex(txt.getBytes());
    }
 
    private String fromHex(String hex) {
        return new String(toByte(hex));
    }
 
    private String toHex(byte[] buf) {
        if (buf == null)
            return "";
        StringBuffer result = new StringBuffer(2 * buf.length);
        for (int i = 0; i < buf.length; i++) {
            appendHex(result, buf[i]);
        }
        return result.toString();
    }
 
    private void appendHex(StringBuffer sb, byte b) {
        sb.append(HEX.charAt((b >> 4) & 0x0f)).append(HEX.charAt(b & 0x0f));
    }



    public static final String PUBLIC_KEY_STR = "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAILho76AqLkeilrjmOUCKhXQAe9Ul4QzfiS/y0HXmdx64mPtvukXi++dJGTWuIMxwlXR4+0ynb1yPRX+hV10yAkCAwEAAQ==";
    public static void main(String[] args) {
        AESCrypt aesCrypt = new AESCrypt();
        String content = PUBLIC_KEY_STR;
        String password = "da09a9528b9c710addd8439684e09608";
        try {
            //Log.i("dddddddddddddddd", "加密文本为" + content);
            String encryptingCode = aesCrypt.encrypt(password, content);
            Log.i("dddddddddddddddd", "加密结果为 " + encryptingCode);
            String decryptingCode = aesCrypt.decrypt(password, encryptingCode);
            Log.i("dddddddddddddddd", "解密结果为 " + decryptingCode);
        } catch (Exception e) {
            Log.i("dddddddddddddddd", "e " + e);
            e.printStackTrace();
        }
    }

}
