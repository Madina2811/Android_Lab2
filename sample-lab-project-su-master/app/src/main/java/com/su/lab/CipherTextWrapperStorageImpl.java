package com.su.lab;

import android.content.Context;

public class CipherTextWrapperStorageImpl implements CipherTextWrapperStorage {

    private static final String SHARED_PREF_FILE_NAME = "login_prefs";
    private static final String PIN_KEY = "pin";
    private static final String PIN_IV_KEY = "pin_iv";

    @Override
    public void persistCipherTextWrapper(Context context, CipherTextWrapper wrapper) {
        /*
         *  TODO #1 Реализовать сохрание шифр. текста cipherText и вектора инициализации initializationVector
         *    из CipherTextWrapper в SharedPreferences, используя ключи PIN_KEY и PIN_IV_KEY
         *  https://www.fandroid.info/sharedpreferences-sohranenie-dannyh-v-postoyannoe-hranilishhe-android/
         *
         */
    }

    @Override
    public CipherTextWrapper getCipherTextWrapper(Context context) {
        String cipherText = null;
        String initializationVector = null;
        /*
         *  TODO #2 Реализовать получение шифр. текста cipherText и вектора инициализации initializationVector
         *    из SharedPreferences, используя ключи PIN_KEY и PIN_IV_KEY, название файла SharedPreference SHARED_PREF_FILE_NAME
         *    https://www.fandroid.info/sharedpreferences-sohranenie-dannyh-v-postoyannoe-hranilishhe-android/
         *
         */
        if (cipherText == null || initializationVector == null) {
            return null;
        }
        return new CipherTextWrapper(cipherText, initializationVector);
    }

    @Override
    public boolean isCipherTextWrapperExist(Context context) {
        return this.getCipherTextWrapper(context) != null;
    }
}
