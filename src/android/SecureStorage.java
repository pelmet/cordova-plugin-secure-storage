package com.crypho.plugins;

import java.lang.reflect.Method;

import android.util.Log;
import android.util.Base64;
import android.os.Build;
import android.app.KeyguardManager;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;

import org.apache.cordova.CallbackContext;
import org.apache.cordova.CordovaArgs;
import org.apache.cordova.CordovaPlugin;
import org.json.JSONException;
import org.json.JSONObject;
import org.json.JSONArray;
import java.util.Set;
import javax.crypto.Cipher;

import com.facebook.android.crypto.keychain.AndroidConceal;
import com.facebook.android.crypto.keychain.SharedPrefsBackedKeyChain;
import com.facebook.crypto.Crypto;
import com.facebook.crypto.CryptoConfig;
import com.facebook.crypto.Entity;
import com.facebook.crypto.keychain.KeyChain;

import java.nio.charset.Charset;

public class SecureStorage extends CordovaPlugin {
    private static final String TAG = "SecureStorage";

    public static final String KEYCHAIN_MODULE = "SecureStorage";
    public static final String KEYCHAIN_DATA = "IONIC_KEYCHAIN";
    public static final String EMPTY_STRING = "";
    private static final String MIGRATED_TO_NATIVE_KEY = "_SS_MIGRATED_TO_NATIVE";
    private static final String MIGRATED_TO_NATIVE_STORAGE_KEY = "_SS_MIGRATED_TO_NATIVE_STORAGE";

    protected Crypto crypto;
    protected SharedPreferences prefs;

    @Override
    public void onResume(boolean multitasking) {

        if (crypto == null) {
            cordova.getThreadPool().execute(new Runnable() {
                public void run() {
                    init();
                }
            });
        }
    }

    protected void init() {
        KeyChain keyChain = new SharedPrefsBackedKeyChain(getContext(), CryptoConfig.KEY_256);
        crypto = AndroidConceal.get().createDefaultCrypto(keyChain);
        prefs = getContext().getSharedPreferences(KEYCHAIN_DATA, Context.MODE_PRIVATE);
    }

    @Override
    public boolean execute(String action, CordovaArgs args, final CallbackContext callbackContext) throws JSONException {
        if ("init".equals(action)) {

            init();

            int SUPPORTS_NATIVE_AES = Build.VERSION.SDK_INT >= 21 ? 1 : 0;
            callbackContext.success(SUPPORTS_NATIVE_AES);
        }
        if ("set".equals(action)) {
            final String key = args.getString(0);
            final String value = args.getString(1);
            final String adata = args.getString(2);

            cordova.getThreadPool().execute(new Runnable() {
                public void run() {
                    setKey(key, value, callbackContext);
                }
            });
            return true;
        }
        if ("get".equals(action)) {
            final String key = args.getString(0);

            cordova.getThreadPool().execute(new Runnable() {
                public void run() {
                    getKey(key, callbackContext);
                }
            });
            return true;
        }
        if ("decrypt_rsa".equals(action)) {
            return false;
        }
        if ("encrypt_rsa".equals(action)) {
            return false;
        }

        if ("secureDevice".equals(action)) {
            return false;
        }
        //SharedPreferences interface
        if ("remove".equals(action)) {
            String key = args.getString(0);

            SharedPreferences.Editor prefsEditor = prefs.edit();

            if (prefs.contains(createName(key))) {
                prefsEditor.remove(createName(key));
                prefsEditor.apply();
                callbackContext.success("KeychainModule password was reset");
            }

            return true;
        }
        if ("store".equals(action)) {
            String key = args.getString(0);
            String value = args.getString(1);

            SharedPreferences.Editor prefsEditor = prefs.edit();
            prefsEditor.putString(key, value);
            prefsEditor.apply();

            callbackContext.success();
            return true;
        }
        if ("fetch".equals(action)) {
            String key = args.getString(0);
            String data = prefs.getString(key, "not_found");
            if (data.equals("not_found")) {
                callbackContext.error("Key [" + key + "] not found.");
            } else {
                callbackContext.success(data);
            }
            return true;
        }
        if ("keys".equals(action)) {
            Set res = prefs.getAll().keySet();
            res.remove(MIGRATED_TO_NATIVE_KEY);
            res.remove(MIGRATED_TO_NATIVE_STORAGE_KEY);

            callbackContext.success(new JSONArray(res));
            return true;
        }
        if ("clear".equals(action)) {
            callbackContext.success();
            return true;
        }
        return false;

    }

    private Context getContext() {
        return cordova.getActivity().getApplicationContext();
    }

    private void startActivity(Intent intent) {
        cordova.getActivity().startActivity(intent);
    }


    protected void getKey(String key, final CallbackContext callbackContext) {
        String data = prefs.getString(createName(key), "not_found");
        if (data.equals("not_found")) {
            Log.e(KEYCHAIN_MODULE, "no keychain entry found for key: " + key);
            callbackContext.error("no keychain entry found for key: " + key);
            return;
        }

        byte[] recdata = Base64.decode(data, Base64.DEFAULT);
        Entity dataentity = Entity.create(createName(key));

        try {
            byte[] decryptedData = crypto.decrypt(recdata, dataentity);
            callbackContext.success(new String(decryptedData, Charset.forName("UTF-8")));
        } catch (Exception e) {
            Log.e(KEYCHAIN_MODULE, e.getLocalizedMessage());
            callbackContext.error(e.getLocalizedMessage());
        }
    }

    protected void setKey(String key, String value, final CallbackContext callbackContext) {
        if (!crypto.isAvailable()) {
            Log.e(KEYCHAIN_MODULE, "Crypto is missing");
            callbackContext.error("KeychainModule: crypto is missing");
            return;
        }

        Entity dataentity = Entity.create(createName(key));
        String encryptedData = encryptWithEntity(value, dataentity, callbackContext);

        SharedPreferences.Editor prefsEditor = prefs.edit();
        prefsEditor.putString(createName(key), encryptedData);
        prefsEditor.apply();
        Log.d(KEYCHAIN_MODULE, "saved the data");
        callbackContext.success();
    }

    protected String createName(String key) {
        return KEYCHAIN_DATA + ":" + key;
    }

    private String encryptWithEntity(String toEncypt, Entity entity, final CallbackContext callbackContext) {
        try {
            byte[] encryptedBytes = crypto.encrypt(toEncypt.getBytes(Charset.forName("UTF-8")), entity);
            return Base64.encodeToString(encryptedBytes, Base64.DEFAULT);
        } catch (Exception e) {
            Log.e(KEYCHAIN_MODULE, e.getLocalizedMessage());
            callbackContext.error(e.getLocalizedMessage());
            return null;
        }

    }
}
