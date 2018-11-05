package com.felix.cipherlibrary;

/**
 * Created by Felix.Zhong on 2018/9/29 12:07
 * Application of common salt value
 */
public enum Salt {
    /**
     * 签名的盐
     */
    SALT_SIGNATURE {
        @Override
        public String getSalt() {
            return "aaaaa";
        }
    },
    /**
     * 公钥解密的盐
     */
    SALT_PUBLIC_KEY {
        @Override
        public String getSalt() {
            return "aaaaa";
        }
    },
    /**
     * 用户密码的盐
     */
    SALT_PASSWORD {
        @Override
        public String getSalt() {
            return "aaaaa";
        }
    };

    public abstract String getSalt();
}
