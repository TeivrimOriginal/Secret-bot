package com.secretbot.app;

/**
 * Проверка BridgeLogic обычным запуском java.
 *
 * Собирается и выполняется скриптом android/test-bridge.py. Текст ошибок
 * печатается в stdout, код возврата 1 означает «есть поломки».
 *
 * Зачем отдельный класс, а не проверки внутри test-bridge.py: правила должны
 * проверяться на тех же данных, что и в приложении. Копия логики на Python
 * разойдётся с Java при первом же изменении — и будет врать.
 */
public final class BridgeLogicTest {

    private static int failures = 0;
    private static int checks = 0;

    public static void main(String[] args) {
        // --- безопасное имя ---
        equals("простое имя не трогаем", "отчёт.pdf", BridgeLogic.safeName("отчёт.pdf"));
        equals("пробелы по краям убираются", "file.pdf", BridgeLogic.safeName("  file.pdf  "));
        equals("разделитель пути заменяется", ".._.._etc_passwd",
                BridgeLogic.safeName("../../etc_passwd"));
        // Двоеточие И слеш — два разделителя, значит и два подчёркивания.
        equals("обратный слеш заменяется", "C__temp_x.txt", BridgeLogic.safeName("C:\\temp\\x.txt"));
        equals("двоеточие заменяется", "a_b.txt", BridgeLogic.safeName("a:b.txt"));
        equals("пустое имя -> file", "file", BridgeLogic.safeName(""));
        equals("null -> file", "file", BridgeLogic.safeName(null));
        equals("только пробелы -> file", "file", BridgeLogic.safeName("   "));

        // Имя из одних точек указывало бы на сам каталог — это не имя файла.
        equals("точка -> file", "file", BridgeLogic.safeName("."));
        equals("две точки -> file", "file", BridgeLogic.safeName(".."));
        equals("много точек -> file", "file", BridgeLogic.safeName("...."));
        // Подчёркивания оставляем: имя не должно указывать на каталог.
        equals("подчёркивание остаётся", "my_file.txt", BridgeLogic.safeName("my_file.txt"));

        String longName = repeat("я", 300) + ".txt";
        String trimmed = BridgeLogic.safeName(longName);
        check("длинное имя обрезано до 120", trimmed.length() == 120);

        // В имени не должно остаться ничего, что уводит за пределы каталога.
        String nasty = "../../../system/etc/shadow";
        String safe = BridgeLogic.safeName(nasty);
        check("в имени не осталось разделителей", safe.indexOf('/') < 0 && safe.indexOf('\\') < 0);
        check("имя не равно двум точкам", !safe.equals(".."));

        // Управляющие символы (например \n) в имя файла попадать не должны:
        // иначе имя разъедется при выводе в терминал.
        equals("перевод строки заменяется", "a_b.txt", BridgeLogic.safeName("a\nb.txt"));

        // --- оценка размера ---
        equals("пустая строка — 0 байт", 0L, BridgeLogic.estimatedBytes(""));
        equals("null — 0 байт", 0L, BridgeLogic.estimatedBytes(null));
        equals("4 символа без padding — 3 байта", 3L, BridgeLogic.estimatedBytes("QUJD"));
        equals("один padding убирается", 2L, BridgeLogic.estimatedBytes("QUI="));
        equals("два padding убираются", 1L, BridgeLogic.estimatedBytes("QQ=="));
        // «QUJDREVG» — 8 символов, значит 6 байт, а не 9.
        equals("8 символов — 6 байт", 6L, BridgeLogic.estimatedBytes("QUJDREVG"));
        equals("12 символов — 9 байт", 9L, BridgeLogic.estimatedBytes("QUJDREVGSElK"));
        equals("с пустыми строками", 0L, BridgeLogic.estimatedBytes("   "));

        // --- проверка перед записью ---
        equals("нормальный файл проходит", null,
                BridgeLogic.checkPayload("QUJDREVGR0hJSktM"));
        equals("пустые данные отклонены", "страница прислала пустые данные",
                BridgeLogic.checkPayload("   "));
        equals("null отклонён", "страница прислала пустые данные",
                BridgeLogic.checkPayload(null));

        // Лимит — главная причина существования этого класса. Проверяем на
        // маленьком лимите: с настоящими 32 МБ тесту пришлось бы строить строки
        // по 44 млн символов, и он падал бы от нехватки памяти, а не сообщал
        // о своей пользе. Ветка кода — та же самая.
        int maxBytes = BridgeLogic.MAX_BYTES;
        check("боевой лимит разумный (1..128 МБ)",
                maxBytes > 0 && maxBytes <= 128 * 1024 * 1024);

        final int small = 300; // лимит для проверки — 300 байт
        // 400 символов без padding — ровно 300 байт, то есть ровно лимит.
        // 404 символа — уже 303 байта, то есть перебор.
        String atLimit = repeat("A", 400);
        String justOver = repeat("A", 404);

        equals("400 символов это ровно 300 байт", 300L, BridgeLogic.estimatedBytes(atLimit));
        equals("404 символа это уже 303 байта", 303L, BridgeLogic.estimatedBytes(justOver));

        check("файл ровно в лимите проходит",
                BridgeLogic.checkPayload(atLimit, small) == null);
        check("файл сверх лимита отклонён",
                BridgeLogic.checkPayload(justOver, small) != null);

        String error = BridgeLogic.checkPayload(justOver, small);
        check("в ошибке есть слово «лимит»", error != null && error.contains("лимит"));
        // Раньше при маленьком лимите сообщение выходило «больше лимита 0 МБ» —
        // размер меньше мегабайта печатался целыми мегабайдами и обнулялся.
        check("в ошибке размер в КБ, а не «0 МБ»",
                error != null && error.contains("КБ"));

        // Заведомо большой файл: 1 МБ base64 при лимите 300 байт.
        check("явно большой файл отклонён",
                BridgeLogic.checkPayload(repeat("A", 1000000), small) != null);

        // Проверка без аргумента должна идти по боевому лимиту, и маленький
        // файл через неё проходить.
        check("маленький файл проходит и через боевой лимит",
                BridgeLogic.checkPayload("QUJDREVG") == null);

        System.out.println("проверок: " + checks + ", поломок: " + failures);
        if (failures > 0) {
            System.exit(1);
        }
    }

    private static String repeat(String text, int times) {
        StringBuilder builder = new StringBuilder(text.length() * times);
        for (int i = 0; i < times; i++) {
            builder.append(text);
        }
        return builder.toString();
    }

    private static void equals(String title, Object expected, Object actual) {
        checks++;
        boolean ok = expected == null ? actual == null : expected.equals(actual);
        if (ok) {
            System.out.println("  ok  " + title);
        } else {
            failures++;
            System.out.println("  FAIL " + title
                    + " — ждали <" + expected + ">, получили <" + actual + ">");
        }
    }

    private static void check(String title, boolean condition) {
        checks++;
        if (condition) {
            System.out.println("  ok  " + title);
        } else {
            failures++;
            System.out.println("  FAIL " + title);
        }
    }
}
