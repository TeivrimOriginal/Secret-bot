# Secret-bot для Android

Обёртка над страницей сайта: без адресной строки, с сохранённым адресом и
возможностью открыть ссылку извне. Бот на Android не запускается — он
серверный процесс (long polling), и на телефоне открывают страницу
расшифровки.

Ноль сборки: обычный путь — PWA (см. README проекта, раздел «Android»).
Этот каталог нужен, когда нужен настоящий apk: ярлык с иконкой в лаунчере,
без адресной строки и без зависимости от браузера.

## Что внутри

```
android/
├── app/src/main/java/com/secretbot/app/MainActivity.java   всё приложение
├── app/src/main/AndroidManifest.xml                       + deep link secretbot://open?url=...
├── app/src/main/res/…                                     разметка, тема, иконки
├── make-icons.py                                          рисует mipmap-* из build/make-icon.py
├── check-java.py                                          разбор Java без Android SDK
└── gradle/wrapper/gradle-wrapper.properties               версия Gradle 8.7
```

## Три вещи, без которых обёртка не работает

1. **Навигация ограничена хостом из настроек.** Внешние ссылки открываются
   системным браузером. Иначе любой сайт, открытый внутри WebView, получил бы
   мост `AndroidFile` и запись в файлы приложения.
2. **Мост `AndroidFile`.** WebView не умеет скачивать `blob:`-ссылку, которой
   страница отдаёт расшифрованный файл. Страница вместо `<a download>`
   вызывает мост с base64 (`window.AndroidFile.saveBase64`), мост пишет файл
   в `Android/data/com.secretbot.app/files/Download` — права не нужны ни на
   одной версии Android. Путь показывается тостом.
3. **Passkey в WebView зависит от версии WebView.** Если кнопки «Войти по
   Face ID / отпечатку» нет, открывайте ту же ссылку в Chrome: путь через
   PWA/браузер гарантирован, там же работает и по HTTPS-требованию WebAuthn.

## Сборка

Нужен Android SDK (compileSdk 34) и Gradle 8.7+ с AGP 8.5.2.

```bash
# иконки запуска обязательны: манифест ссылается на @mipmap/ic_launcher
python android/make-icons.py

# Android Studio: открыть каталог android/ и собрать
# или вручную, если Gradle уже установлен:
gradle assembleDebug        # app/build/outputs/apk/debug/app-debug.apk
```

**Осторожно:** в репозитории нет `gradle-wrapper.jar` и скриптов `gradlew` —
они весят около 60 КБ и тянутся из сети при первой сборке. Пока их нет,
используйте локальный Gradle или Android Studio (он добавит wrapper сам).

## Что проверено, а что нет

| Проверка | Статус |
|---|---|
| `python android/make-icons.py` | ✅ 10 иконок, размеры сверены |
| `python android/check-java.py` | ✅ синтаксис разбирается javac |
| `python ../test-passkey.py` | ✅ 73 проверки, включая ветку моста на странице |
| `gradle assembleDebug` | ⚠️ не запускалось: на машине нет Android SDK |

`check-java.py` — честный минимум: без `android.jar` javac не может проверить
типы, но на синтаксическую ошибку (лишняя скобка) ругается всегда. Проверено
негативным тестом: сломанная скобка даёт «illegal start of expression», и
проверка её показывает, а не прячет среди «нет android.jar».

## Чего приложение не делает

* Не шифрует и не расшифровывает ничего самостоятельно — вся криптография на
  сервере, ключ в приложение не попадает.
* Не запускает бота (для этого Termux, см. README проекта).
* Не показывает push о новых файлах: у сайта нет ленты, а опрос в фоне
  Android всё равно усыпляет.
