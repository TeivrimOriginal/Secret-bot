package com.secretbot.app;

import android.annotation.SuppressLint;
import android.app.Activity;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.ApplicationInfo;
import android.net.Uri;
import android.os.Bundle;
import android.os.Environment;
import android.util.Base64;
import android.view.View;
import android.webkit.JavascriptInterface;
import android.webkit.WebResourceRequest;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.EditText;
import android.widget.Toast;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;

/**
 * Android-версия Secret-bot.
 *
 * Бот — серверный процесс (long polling), поэтому на Android открывают
 * страницу. Это приложение — полноэкранная обёртка над ней: при первом
 * запуске спрашивает адрес сайта (BASE_URL) либо сразу полную ссылку
 * вида https://host/d/токен, сохраняет и дальше открывает страницу как
 * обычное приложение, без адресной строки.
 *
 * Три вещи, без которых обёртка не работает:
 *   1. Навигация ограничена хостом из настроек. Внешние ссылки (например,
 *      из текста страницы) открываются системным браузером — иначе любой
 *      сайт, открытый внутри, получил бы мост AndroidFile.
 *   2. WebView не умеет скачивать blob-ссылку, которой страница отдаёт
 *      расшифрованный файл. Мост AndroidFile принимает base64 и пишет файл
 *      в «Файлы/Android/data/com.secretbot.app/files/Download» — права
 *      не нужны ни на одной версии Android.
 *   3. Passkey в WebView зависит от версии WebView; если кнопки «Войти по
 *      Face ID» нет — открывайте ту же ссылку в Chrome, там путь гарантирован.
 *
 * Сменить адрес: долгий тап по странице.
 * Открыть ссылку извне: Android выберет Secret-bot для
 * secretbot://open?url=https://host/d/токен
 */
public class MainActivity extends Activity {

    private static final String PREFS = "secretbot";
    private static final String KEY_URL = "base_url";
    private static final String BRIDGE = "AndroidFile";

    private WebView webView;
    private View configView;
    private EditText urlInput;
    private String host = "";

    @SuppressLint("SetJavaScriptEnabled")
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        webView = findViewById(R.id.webview);
        configView = findViewById(R.id.config_view);
        urlInput = findViewById(R.id.url_input);

        // Debug-сборка открывает devtools-сокет WebView. Без этого проверить
        // приложение можно только по скриншоту глазами: страница внутри
        // WebView недоступна, и результат вызова моста не прочитать.
        // В release флаг не выставлен — сокет остаётся закрытым.
        if ((getApplicationInfo().flags & ApplicationInfo.FLAG_DEBUGGABLE) != 0) {
            WebView.setWebContentsDebuggingEnabled(true);
        }

        WebSettings s = webView.getSettings();
        s.setJavaScriptEnabled(true);
        s.setDomStorageEnabled(true);
        s.setAllowFileAccess(false);
        s.setAllowContentAccess(false);
        webView.addJavascriptInterface(new FileBridge(), BRIDGE);

        // Долгий тап — сменить ссылку. Отдельной кнопки нет намеренно:
        // страница должна выглядеть как приложение, а не как браузер.
        webView.setOnLongClickListener(new View.OnLongClickListener() {
            @Override
            public boolean onLongClick(View v) {
                showConfig();
                return true;
            }
        });

        webView.setWebViewClient(new WebViewClient() {
            @Override
            public boolean shouldOverrideUrlLoading(WebView view, WebResourceRequest request) {
                Uri uri = request.getUrl();
                if (isOurHost(uri)) {
                    return false;
                }
                startActivity(new Intent(Intent.ACTION_VIEW, uri));
                return true;
            }
        });

        String saved = prefs().getString(KEY_URL, "");
        if (!handleDeepLink(getIntent())) {
            if (saved.isEmpty()) {
                showConfig();
            } else {
                load(saved);
            }
        }
    }

    private SharedPreferences prefs() {
        return getSharedPreferences(PREFS, MODE_PRIVATE);
    }

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        setIntent(intent);
        handleDeepLink(intent);
    }

    /**
     * secretbot://open?url=... — открыть ссылку извне (например, из меню
     * «Открыть с помощью»). Возвращает true, если адрес был и открыт.
     */
    private boolean handleDeepLink(Intent intent) {
        if (intent == null || intent.getData() == null) {
            return false;
        }
        Uri data = intent.getData();
        if (!"secretbot".equals(data.getScheme())) {
            return false;
        }
        String url = data.getQueryParameter("url");
        if (url == null || url.trim().isEmpty()) {
            return false;
        }
        url = normalize(url);
        prefs().edit().putString(KEY_URL, url).apply();
        load(url);
        return true;
    }

    /** Приводит адрес к виду https://host/... — то, что понимает WebView. */
    private static String normalize(String raw) {
        String url = raw.trim();
        if (!url.startsWith("http://") && !url.startsWith("https://")) {
            url = "https://" + url;
        }
        return url;
    }

    private boolean isOurHost(Uri uri) {
        return host != null && !host.isEmpty() && host.equalsIgnoreCase(uri.getHost());
    }

    private void load(String url) {
        url = normalize(url);
        Uri uri = Uri.parse(url);
        host = uri.getHost() == null ? "" : uri.getHost();
        configView.setVisibility(View.GONE);
        webView.setVisibility(View.VISIBLE);
        webView.loadUrl(url);
    }

    private void showConfig() {
        urlInput.setText(prefs().getString(KEY_URL, ""));
        webView.setVisibility(View.GONE);
        configView.setVisibility(View.VISIBLE);
    }

    /** Кнопка «Сохранить и открыть» на экране настройки адреса. */
    public void onSaveUrl(View v) {
        String url = urlInput.getText().toString().trim();
        if (url.isEmpty()) {
            return;
        }
        url = normalize(url);
        prefs().edit().putString(KEY_URL, url).apply();
        load(url);
    }

    @Override
    public void onBackPressed() {
        if (webView.getVisibility() == View.VISIBLE && webView.canGoBack()) {
            webView.goBack();
        } else {
            super.onBackPressed();
        }
    }

    /**
     * Мост страницы -> устройство: страница отдаёт файл в base64, мост
     * кладёт его в каталог приложения. Вызывается из JS-потока WebView,
     * поэтому Toast уходит в главный поток.
     */
    public class FileBridge {

        @JavascriptInterface
        public boolean saveBase64(String base64, String fileName) {
            final String target;
            try {
                // Проверки и безопасное имя — в BridgeLogic, они покрыты
                // android/test-bridge.py. Здесь только запись на диск.
                String tooBig = BridgeLogic.checkPayload(base64);
                if (tooBig != null) {
                    notify("❌ " + tooBig);
                    return false;
                }
                byte[] data = Base64.decode(base64, Base64.DEFAULT);
                File dir = getExternalFilesDir(Environment.DIRECTORY_DOWNLOADS);
                if (dir == null) {
                    dir = new File(getFilesDir(), "Download");
                }
                if (!dir.exists() && !dir.mkdirs()) {
                    throw new IOException("не удалось создать каталог " + dir);
                }
                File out = new File(dir, BridgeLogic.safeName(fileName));
                try (FileOutputStream os = new FileOutputStream(out)) {
                    os.write(data);
                }
                target = out.getAbsolutePath();
            } catch (OutOfMemoryError exc) {
                // Строка от страницы оказалась слишком большой для кучи. Ловим
                // отдельно от Exception: это Error, обычный catch мимо.
                notify("❌ Файл слишком большой, памяти не хватило");
                return false;
            } catch (Exception exc) {
                notify("❌ Не удалось сохранить файл: " + exc.getMessage());
                return false;
            }
            notify("✅ Сохранено: " + target);
            return true;
        }

        private void notify(final String text) {
            runOnUiThread(new Runnable() {
                @Override
                public void run() {
                    Toast.makeText(MainActivity.this, text, Toast.LENGTH_LONG).show();
                }
            });
        }
    }
}
