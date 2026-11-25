# راهنمای اتصال Idol Security Scanner به Idol Store

## آدرس عمومی گزارش

```
https://raw.githubusercontent.com/Alvandcode/idol-store-catalog/main/security-results.json
```

این همان آدرسی است که اپلیکیشن اندروید در `SecurityRepository.kt` می‌خواند.

## سازگاری اسکیمای v2 با اپ (بدون تغییر در اپ)

اسکنر v2 برای حفظ سازگاری، فیلدهای قدیمی را نگه می‌دارد و فیلدهای جدید اضافه می‌کند:

| فیلد v1 (قبلی اپ) | در v2 | توضیح |
|---|---|---|
| `results[].id` | ✅ | شناسه برنامه (عیناً از `apps.json`) |
| `results[].status` | ✅ | مستعار سازگار: `no_detection`/`warning`/`dangerous`/`incomplete`/`not_scanned`/`scan_error` |
| `results[].release.tag` | ✅ (`release_version`) | نسخه اسکن‌شده |
| `results[].source.status` | ✅ (تحت `source_scan`) | وضعیت اسکن سورس |
| `results[].source.dependencyAudit.status` | ✅ | وضعیت OSV |
| `assets[].name/sha256/status` | ✅ (تحت `scanned_assets`) | وضعیت هر فایل انتشار |

فیلدهای جدید v2 که اپ می‌تواند تدریجی مصرف کند (`ignoreUnknownKeys = true`):
`overall_status` (SAFE/LOW_RISK/WARNING/…), `risk_level`, `scan_timestamp`,
`scanner_version`, `detections`, `vulnerabilities`, `warnings`, `scan_errors`,
`skipped_files`, `sha256_after_scan`, `integrity_verified`, `summary`.

## قواعد نمایش در اپ

- **DANGEROUS** (`status: "dangerous"`) → دانلود مسدود (اپ فعلی این را از قبل اعمال می‌کند: `StoreViewModel.canDownload`).
- **INCOMPLETE** (`status: "incomplete"`) → هرگز نشان تأیید امنیت نمایش داده نشود؛ پیام «اسکن کامل نشده».
- **بدون گزارش** → «اسکن‌نشده»؛ معنای سالم بودن ندارد.
- **SHA-256** فایل دانلودی باید با `scanned_assets[].sha256` همان `release_version` مقایسه شود؛ عدم تطابق → توقف دانلود یا هشدار جدی (فایل جایگزین‌شده است).
- رنگ‌ها: سبز = تهدید شناسایی نشده، زرد = نیاز به بازبینی (warning)، نارنجی = اسکن ناقص، قرمز = تهدید قطعی (مسدود).

## انطباق نسخه

اپ باید قبل از اعتماد به گزارش، `release.tag == نسخه ریلیز فعلی` را چک کند — نتایج نسخه‌های دیگر برای نسخه جدید معتبر نیستند. این منطق از قبل در `StoreViewModel` وجود دارد و حفظ شده است.

## اجرای اسکن

1. تغییر کاتالوگ یا هفتگی یا دستی → Actions → *Idol Security Scan v2*.
2. گزارش + کش (`security-cache/`) با کامیت ربات در `main` منتشر می‌شود.
3. اپ آدرس خام بالا را می‌خواند (کش‌شده با `Cache-Control: no-cache`).
