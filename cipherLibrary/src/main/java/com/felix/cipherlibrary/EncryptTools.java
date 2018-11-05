package com.felix.cipherlibrary;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;

/**
 * Created by Felix.Zhong on 2018/7/26 17:44
 * Encryption tool class
 */
public class EncryptTools {
    /**
     * Or encryption and decryption, which is suitable for partial encryption of the entire file, such as the header and tail of the file.
     * Encrypt the header and tail of file file, which is suitable for zip compression package encryption.
     *
     * @param source Encrypted files
     * @param det    加密后保存文件名
     * @param key    加密key
     */
    public static void encryptionFile(File source, File det, int key) {
        FileInputStream fis = null;
        FileOutputStream fos = null;
        try {
            fis = new FileInputStream(source);
            fos = new FileOutputStream(det);
            int size = 2048;
            byte[] buff = new byte[size];
            int count = fis.read(buff);
            /* Zip package Head encryption*/
            for (int i = 0; i < count; i++) {
                fos.write(buff[i] ^ key);
            }
            while (true) {
                count = fis.read(buff);
                /*Zip packet end encryption*/
                if (count < size) {
                    for (int j = 0; j < count; j++) {
                        fos.write(buff[j] ^ key);
                    }
                    break;
                }
                fos.write(buff, 0, count);
            }
            fos.flush();
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            try {
                if (fis != null) {
                    fis.close();
                }
                if (fos != null) {
                    fos.close();
                }
            } catch (IOException e) {
                e.printStackTrace();
            }

        }
    }

    /**
     * Or encryption and decryption, which is suitable for encrypting the entire file.
     *
     * @param source Path to encrypt files
     * @param det    加密后保存文件的路径
     * @param key    加密秘钥key
     */
    private static void encryptionFile(String source, String det, int key) {
        FileInputStream fis = null;
        FileOutputStream fos = null;
        try {
            fis = new FileInputStream(source);
            fos = new FileOutputStream(det);
            int read;
            while ((read = fis.read()) != -1) {
                fos.write(read ^ key);
            }
            fos.flush();
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            try {
                if (fis != null) {
                    fis.close();
                }
                if (fos != null) {
                    fos.close();
                }
            } catch (IOException e) {
                e.printStackTrace();
            }

        }
    }
}
