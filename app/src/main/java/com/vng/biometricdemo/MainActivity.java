package com.vng.biometricdemo;

import android.annotation.TargetApi;
import android.content.Context;
import android.content.DialogInterface;
import android.content.SharedPreferences;
import android.hardware.biometrics.BiometricPrompt;
import android.os.Build;
import android.os.Bundle;
import android.os.CancellationSignal;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyPermanentlyInvalidatedException;
import android.security.keystore.KeyProperties;
import android.support.annotation.Nullable;
import android.support.v4.hardware.fingerprint.FingerprintManagerCompat;
import android.support.v7.app.AppCompatActivity;
import android.text.TextUtils;
import android.util.Base64;
import android.util.Log;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

/**
 * Copyright (C) 2019, VNG Corporation.
 *
 * @author namnt4
 * @since 24/07/2019
 */

@TargetApi(23)
public class MainActivity extends AppCompatActivity {

    private static final String KEY_NAME = "PaymentPassword";

    private static final String PREF_KEY_PASSWORD = "key_password";

    private static final String PREF_KEY_IV = "key_iv";

    private KeyStore mKeyStore;
    private KeyGenerator mKeyGenerator;
    private Cipher mCipher;
    private SharedPreferences mPreferences;
    private byte[] mIV;

    private EditText mPasswordInput;
    private TextView mOutputView;

    private final CancellationSignal mCancellationSignal = new CancellationSignal();

    @TargetApi(28)
    private final BiometricPrompt.AuthenticationCallback mAuthenticationCallback = new BiometricPrompt.AuthenticationCallback() {
        @Override
        public void onAuthenticationError(int errorCode, CharSequence errString) {
            super.onAuthenticationError(errorCode, errString);
            onDecryptFailed();
        }

        @Override
        public void onAuthenticationHelp(int helpCode, CharSequence helpString) {
            super.onAuthenticationHelp(helpCode, helpString);
            onDecryptFailed();
        }

        @Override
        public void onAuthenticationSucceeded(BiometricPrompt.AuthenticationResult result) {
            super.onAuthenticationSucceeded(result);
            try {
                final String encryptedPassword = mPreferences.getString(PREF_KEY_PASSWORD, "");
                final String decryptedPassword;
                if (TextUtils.isEmpty(encryptedPassword)) {
                    decryptedPassword = "Invalid";
                } else {
                    final byte[] decode = Base64.decode(encryptedPassword, Base64.NO_WRAP);
                    decryptedPassword = new String(mCipher.doFinal(decode));
                }
                mOutputView.setText(decryptedPassword);
            } catch (BadPaddingException e) {
                e.printStackTrace();
            } catch (IllegalBlockSizeException e) {
                e.printStackTrace();
            }
        }

        @Override
        public void onAuthenticationFailed() {
            super.onAuthenticationFailed();
        }
    };

    @TargetApi(28)
    private final BiometricPrompt.AuthenticationCallback  mEnableBiometricCallback = new BiometricPrompt.AuthenticationCallback() {
        @Override
        public void onAuthenticationError(int errorCode, CharSequence errString) {
            super.onAuthenticationError(errorCode, errString);
        }

        @Override
        public void onAuthenticationHelp(int helpCode, CharSequence helpString) {
            super.onAuthenticationHelp(helpCode, helpString);
        }

        @Override
        public void onAuthenticationSucceeded(BiometricPrompt.AuthenticationResult result) {
            super.onAuthenticationSucceeded(result);

            final String password = mPasswordInput.getText().toString();
            if (!TextUtils.isEmpty(password)) {
                try {
                    final byte[] bytes = mCipher.doFinal(password.getBytes(StandardCharsets.UTF_8));
                    final String encodedPassword = Base64.encodeToString(bytes, Base64.NO_WRAP);
                    mPreferences.edit().putString(PREF_KEY_PASSWORD, encodedPassword).apply();
                } catch (BadPaddingException e) {
                    e.printStackTrace();
                } catch (IllegalBlockSizeException e) {
                    e.printStackTrace();
                }
            }
        }

        @Override
        public void onAuthenticationFailed() {
            super.onAuthenticationFailed();
        }
    };

    @Override
    protected void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        mPreferences = getSharedPreferences("password_pref" ,Context.MODE_PRIVATE);

        setContentView(R.layout.activity_main);

        mPasswordInput = findViewById(R.id.inputView);
        mOutputView = findViewById(R.id.outputView);

        findViewById(R.id.loginBtn).setOnClickListener(v -> {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                try {
                    final SecretKey key = (SecretKey) mKeyStore.getKey(KEY_NAME, null);
                    mCipher.init(Cipher.ENCRYPT_MODE, key);
                    final byte[] ivBytes = mCipher.getIV();
                    logByteArray(ivBytes);
                    final String iv = Base64.encodeToString(ivBytes, Base64.DEFAULT);
                    Log.d("namnt4", "generated IV = " + iv);
                    mPreferences.edit().putString(PREF_KEY_IV, iv).apply();
                    new BiometricPrompt.Builder(this)
                            .setTitle("Enable using fingerprint")
                            .setSubtitle("Enable using fingerprint subtitle")
                            .setDescription("This is the description")
                            .setNegativeButton("Cancel", getMainExecutor(), this::onCancelEnableBiometricClick)
                            .build()
                            .authenticate(new BiometricPrompt.CryptoObject(mCipher), mCancellationSignal, getMainExecutor(), mEnableBiometricCallback);
                } catch (UnrecoverableKeyException e) {
                    e.printStackTrace();
                } catch (NoSuchAlgorithmException e) {
                    e.printStackTrace();
                } catch (KeyStoreException e) {
                    e.printStackTrace();
                } catch (InvalidKeyException e) {
                    e.printStackTrace();
                }
            }
        });

        findViewById(R.id.loadEncryptPassword).setOnClickListener(v -> {
            final String encryptPassword = mPreferences.getString(PREF_KEY_PASSWORD, "Invalid");
            mOutputView.setText(encryptPassword);
        });

        findViewById(R.id.decryptPassword).setOnClickListener(v -> {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                try {
                    final SecretKey key = (SecretKey) mKeyStore.getKey(KEY_NAME, null);
                    final String iv = mPreferences.getString(PREF_KEY_IV, null);
                    Log.d("namnt4", "saved IV = " + iv);
                    if (iv == null) {
                        return;
                    }
                    final byte[] decode = Base64.decode(iv, Base64.DEFAULT);
                    logByteArray(decode);
                    mCipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(decode));
                    new BiometricPrompt.Builder(this)
                            .setTitle("Authenticate using biometric")
                            .setSubtitle("User your fingerprint")
                            .setDescription("This is the description")
                            .setNegativeButton("Cancel", getMainExecutor(), this::onCancelAuthenByBiometricClick)
                            .build()
                            .authenticate(new BiometricPrompt.CryptoObject(mCipher), mCancellationSignal, getMainExecutor(), mAuthenticationCallback);
                } catch (NoSuchAlgorithmException e) {
                    e.printStackTrace();
                } catch (UnrecoverableKeyException e) {
                    e.printStackTrace();
                } catch (InvalidKeyException e) {
                    e.printStackTrace();
                } catch (InvalidAlgorithmParameterException e) {
                    e.printStackTrace();
                } catch (KeyStoreException e) {
                    e.printStackTrace();
                }
            }
        });

        initCipher();
    }

    private void onDecryptFailed() {
        Toast.makeText(this, "Decrypt failed", Toast.LENGTH_SHORT).show();
    }

    private void onCancelEnableBiometricClick(DialogInterface dialog, int which) {

    }

    protected void onCancelAuthenByBiometricClick(DialogInterface dialog, int which) {

    }

    private void generateKey() {
        try {

            mKeyStore = KeyStore.getInstance("AndroidKeyStore");
            mKeyStore.load(null);

            if (mKeyStore.getKey(KEY_NAME, null) != null) {
                return;
            }

            mKeyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
            mKeyGenerator.init(new KeyGenParameterSpec.Builder(KEY_NAME, KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                    .setUserAuthenticationRequired(true)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
                    .build());

            mKeyGenerator.generateKey();

        } catch (KeyStoreException
                | NoSuchAlgorithmException
                | NoSuchProviderException
                | InvalidAlgorithmParameterException
                | CertificateException
                | IOException exc) {
            exc.printStackTrace();
        } catch (UnrecoverableKeyException e) {
            e.printStackTrace();
        }
    }

    private boolean initCipher() {
        generateKey();
        try {
            mCipher = Cipher.getInstance(
                    KeyProperties.KEY_ALGORITHM_AES + "/"
                            + KeyProperties.BLOCK_MODE_CBC + "/"
                            + KeyProperties.ENCRYPTION_PADDING_PKCS7);
            return true;
        } catch (NoSuchAlgorithmException |
                NoSuchPaddingException e) {
            throw new RuntimeException("Failed to get Cipher", e);
        }
    }

    private void logByteArray(byte[] arr) {
        final StringBuffer buffer = new StringBuffer("ByteArray=[");
        for (int i = 0; i < arr.length; i++) {
            buffer.append(arr[i]);
            if (i != arr.length - 1) {
                buffer.append(",");
            }
        }
        buffer.append("]");
        Log.d("namnt4", buffer.toString());
    }
}
//ByteArray=[-83,90,31,91,-108,105,-78,13,21,90,15,-3,-9,-110,48,-18]