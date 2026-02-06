# Slipstreamplus-CLI
**Coded By : Farhad-UK**

Slipstreamplus-CLI یک ابزار قدرتمند خط فرمان برای **اسکن سریع IP/CIDR** و انجام **تست واقعی تأخیر (RealPing)** با استفاده از Slipstream است. 🚀
این ابزار **داشبورد زنده ترمینال** با پیشرفت، ETA و جدول نتایج ارائه می‌دهد و هم‌زمان از **خروجی‌های مناسب اسکریپت** پشتیبانی می‌کند. 📊🧪

**فارسی | English:** [فارسی](README-FA.md) | [English](README.md)

![Slipstreamplus-CLI Screenshot](screen.jpg)

---

### 🌐 درباره Slipstream
Slipstream با استفاده از پروتکل DNS به شما اجازه می‌دهد از محدودیت‌های شدید و سیستم‌های Whitelisting (لیست سفید) که در سال ۲۰۲۶ اعمال شده عبور کنید. 🔓🛰️
این ابزار با تونل‌کردن ترافیک طوری عمل می‌کند که از شبکه‌هایی عبور کند که فقط DNS را مجاز می‌دانند و حتی زیر فیلترینگ سنگین هم مسیر پایدار فراهم می‌کند. ✅⚡

---

## 🧭 این ابزار چه کاری انجام می‌دهد؟
1. اسکن IP یا CIDR با UDP/53 (DNS probing) 📡
2. شناسایی IPهایی با تونل فعال/کارکرده ✅
3. انجام تست واقعی تأخیر (RealPing) روی IPهای سالم ⏱️
4. نمایش زنده نتایج در ترمینال و/یا ذخیره در فایل 💾

---

## ✨ ویژگی‌ها
- اسکن سریع IP و CIDR (UDP/53) ⚡
- انتخاب تصادفی IP از هر CIDR (اختیاری) 🎲
- رابط کاربری زنده در ترمینال (نوار پیشرفت، ETA، جدول) 📊
- نمایش فقط نتایج موفق در جدول ✅
- RealPing با Slipstream (حالت END بعد از اسکن) 🧪
- RealPing با Slipstream (حالت LIVE حین اسکن) 🔴
- هایلایت سبز برای نتایج موفق RealPing 🟢
- خروجی‌های انعطاف‌پذیر (scan OK / realtest OK) 🗂️
- حالت فقط RealPing (بدون نیاز به اسکن) 🧭

---

## 🧰 پیش‌نیازها

### استفاده از EXE (ویندوز)
- ویندوز 🪟
- بدون نیاز به پایتون ✅

### اجرا از سورس
- Python 3.10+ 🐍
- نصب وابستگی:
```bash
pip install -r requirements.txt
```

---

## 🧪 استفاده پایه

### نمایش راهنما
```bash
slipscan_cli.exe --help
```

```bash
slipscan_cli.exe scan --help
```

```bash
slipscan_cli.exe realtest --help
```

---

## 🔍 دستور Scan

### اجرای سریع (RealPing زنده + ذخیره OK)
```bash
slipscan_cli.exe scan --domain s.domain.top --file iran-ipv4.cidrs --random-per-cidr 8 --threads 100 --timeout-ms 800 --auto-realtest live --realtest-parallel 2 --realtest-slipstream-path .\slipstream-client-windows-amd64.exe --realtest-ok-out real_ok.txt --realtest-ok-format ip
```

### اسکن پایه با رابط زنده
```bash
slipscan_cli.exe scan --domain s.domain.com --file iran-ipv4.cidrs --random-per-cidr 8 --threads 100 --timeout-ms 800 --ui
```

### اسکن بدون UI (حالت اسکریپت)
```bash
slipscan_cli.exe scan --domain s.domain.com --file iran-ipv4.cidrs --random-per-cidr 8 --threads 100 --timeout-ms 800
```

---

## 📥 روش‌های ورودی

### استفاده از فایل
فایل می‌تواند شامل IP یا CIDR باشد:
```
1.1.1.1
8.8.8.0/24
9.9.9.9
```

```bash
--file iran-ipv4.cidrs
```

### وارد کردن مستقیم اهداف
```bash
--targets 1.1.1.1 8.8.8.0/24
```

---

## 🎲 انتخاب تصادفی CIDR
```bash
--random-per-cidr <number>
```

- `0` -> اسکن همه IPهای CIDR (خیلی سنگین است) ⚠️
- `>0` -> انتخاب تصادفی همان تعداد IP از هر CIDR 🎯

مثال:
```bash
--random-per-cidr 8
```

---

## 🧪 حالت‌های RealPing

### حالت END (بعد از اسکن)
```bash
slipscan_cli.exe scan --domain s.domain.com --file iran-ipv4.cidrs --random-per-cidr 8 --threads 100 --timeout-ms 800 --ui --auto-realtest end --realtest-slipstream-path slipstream-client-windows-amd64.exe
```

### حالت LIVE (حین اسکن)
```bash
slipscan_cli.exe scan --domain s.domain.com --file iran-ipv4.cidrs --random-per-cidr 8 --threads 100 --timeout-ms 800 --ui --auto-realtest live --realtest-parallel 2 --realtest-slipstream-path slipstream-client-windows-amd64.exe
```

گزینه‌های پیشنهادی برای LIVE:
```bash
--realtest-ready-ms 5000
--realtest-timeout-s 8
```

---

## 📤 خروجی‌ها

### Scan OK (بدون RealPing)
```bash
--scan-ok-out scan_ok.txt
```

خروجی فایل:
```
87.248.150.222
91.223.116.152
```

---

### RealPing OK (فقط IP)
```bash
--realtest-ok-out real_ok.txt --realtest-ok-format ip
```

```
87.248.150.222
91.223.116.152
```

---

### RealPing OK (IP + تأخیر)
```bash
--realtest-ok-out real_ok_ipms.txt --realtest-ok-format ipms
```

```
87.248.150.222 2340
91.223.116.152 3078
```

---

## 🧭 فقط RealTest (بدون اسکن)
```bash
slipscan_cli.exe realtest --domain s.domain.com --file ips.txt --ui --slipstream-path slipstream-client-windows-amd64.exe --realtest-ok-out ok_ipms.txt --realtest-ok-format ipms
```

---

## 🖥️ نکات UI
- Windows Terminal پیشنهاد می‌شود ✅
- وقتی `--ui` فعال است، خروجی متنی به‌صورت پیش‌فرض غیرفعال است ⚙️
- برای فعال‌سازی stdout از `--stdout` استفاده کنید 🧾

---

## 📝 نکات
- READY TIMEOUT یعنی Slipstream روی آن IP راه‌اندازی نشده است ⏳
- CIDRهای بزرگ بدون انتخاب تصادفی می‌توانند خیلی سنگین باشند ⚠️
- حالت LIVE منتظر تکمیل همه کارهای RealPing می‌ماند ✅
