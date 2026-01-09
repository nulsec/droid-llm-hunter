import os
from typing import List
from core import log

class CodeFilter:
    def __init__(self, decompiled_dir: str, mode: str = "smali", additional_keywords: List[str] = None):
        self.decompiled_dir = decompiled_dir
        self.mode = mode
        
        self.smali_keywords = [
            "Landroid/webkit/WebView;",
            "Landroid/database/sqlite/SQLiteDatabase;->rawQuery",
            "Landroid/database/sqlite/SQLiteDatabase;->execSQL",
            "Landroid/content/SharedPreferences;",
            "Ljavax/crypto/SecretKey;",
            "Ljavax/crypto/Cipher;",
            "Ljava/security/MessageDigest;",
            "Landroid/webkit/WebSettings;->setJavaScriptEnabled",
            "Landroid/webkit/WebView;->addJavascriptInterface",
            "Landroid/webkit/WebView;->loadUrl",
            "Landroid/webkit/WebView;->loadData",
            "Ljava/net/HttpURLConnection;",
            "Lokhttp3/OkHttpClient;",
            "Landroid/hardware/biometrics/BiometricPrompt;",
            "Ljava/io/File;",
            "Landroid/content/ContentProvider;",
            "Landroid/security/keystore/KeyGenParameterSpec;",
        ]
        
        # Keywords for Java Source Code (JADX)
        self.java_keywords = [
            "android.webkit.WebView",
            "SQLiteDatabase", "rawQuery", "execSQL",
            "SharedPreferences",
            "javax.crypto.SecretKey",
            "javax.crypto.Cipher",
            "java.security.MessageDigest",
            "setJavaScriptEnabled",
            "addJavascriptInterface",
            "loadUrl", "loadData",
            "HttpURLConnection",
            "OkHttpClient",
            "BiometricPrompt",
            "java.io.File",
            "ContentProvider",
            "KeyGenParameterSpec"
        ]
        
        # Merge built-in keywords with any dynamic additional keywords
        base_keywords = self.java_keywords if mode == "java" else self.smali_keywords
        self.keywords = base_keywords + (additional_keywords if additional_keywords else [])
        self.extension = ".java" if mode == "java" else ".smali"

    def find_high_value_targets(self) -> List[str]:
        high_value_files = []
        log.info(f"Starting keyword search in {self.decompiled_dir} (Mode: {self.mode})...")
        for root, _, files in os.walk(self.decompiled_dir):
            for file in files:
                if file.endswith(self.extension):
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, "r", encoding="utf-8") as f:
                            content = f.read()
                        if any(keyword in content for keyword in self.keywords):
                            high_value_files.append(file_path)
                            log.debug(f"Found high-value target: {file_path}")
                    except Exception as e:
                        log.warning(f"Could not read file {file_path}: {e}")

        log.success(f"Found {len(high_value_files)} high-value target files.")
        return high_value_files
