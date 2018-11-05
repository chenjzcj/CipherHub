package com.felix.cipherlibrary;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;

/**
 * Created by Felix.Zhong on 2018/7/26 17:44
 * 加密工具类
 */
public class EncryptTools {
    /**
     * 亦或加解密，适合对整个文件的部分加密，比如文件头部，和尾部
     * 对file文件头部和尾部加密，适合zip压缩包加密
     *
     * @param source 需要加密的文件
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
            /*zip包头部加密*/
            for (int i = 0; i < count; i++) {
                fos.write(buff[i] ^ key);
            }
            while (true) {
                count = fis.read(buff);
                /*zip包结尾加密*/
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
     * 亦或加解密，适合对整个文件加密
     *
     * @param source 需要加密文件的路径
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
