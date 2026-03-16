# abuse-guard

اسکریپت یک‌کلیکی برای کاهش abuse report روی سرورهای عمومی VPN/Proxy (مثل Xray/X-UI).

## نصب یک خطی

```bash
# آخرین نسخه از branch اصلی
curl -fsSL https://raw.githubusercontent.com/changecoin938/abuse-xray/main/abuse-guard.sh | sudo bash -s -- install --lockdown
```

اگر خودتان `root` هستید:

```bash
curl -fsSL https://raw.githubusercontent.com/changecoin938/abuse-xray/main/abuse-guard.sh | bash -s -- install --lockdown
```

اگر با خطای `/dev/fd/*` مواجه شدید، علتش این است که `sudo bash <(curl ...)` روی بعضی سرورها FDها را می‌بندد.

## دستورات

```bash
# نصب پیشنهادی برای mixed public node: listenerها را صریح بده
sudo ./abuse-guard.sh install --lockdown --no-auto-detect --listeners-file ./listeners.example.conf

# اگر هر سرور فقط یک سرویس اصلی دارد و همان سرویس الان در حال listen است،
# auto-detect جدید از listener فعال امن‌تر از قبل کار می‌کند
sudo ./abuse-guard.sh install --lockdown

# اگر panel مدیریتی هم عمداً باید با auto-detect باز بماند، این فلگ را صریح بده
sudo ./abuse-guard.sh install --lockdown --auto-allow-panels

# اگر listeners-file داده باشی، auto-detect به‌صورت پیش‌فرض خاموش می‌شود.
# فقط اگر عمداً می‌خواهی هر دو merge شوند:
sudo ./abuse-guard.sh install --lockdown --listeners-file ./listeners.example.conf --merge-auto-detect

# اگر می‌خواهید fallback اسکن عمومی ss هم مجاز باشد (در lockdown ریسک باز شدن پورت‌های اضافی دارد)
sudo ./abuse-guard.sh install --lockdown --allow-ss-fallback

# رفرش خودکار قوانین هر 5 دقیقه (پیش‌فرض)، یا مقدار دلخواه
sudo ./abuse-guard.sh install --lockdown --refresh-interval 300

# غیرفعال‌کردن رفرش دوره‌ای
sudo ./abuse-guard.sh install --lockdown --refresh-interval 0

# اگر عمداً می‌خواهید برای پورت‌های مدیریت‌شده محدودیت TCP بگذارید، دستی و با tuning فعال کنید
sudo ./abuse-guard.sh install --lockdown --in-syn-rate 30 --in-syn-burst 60 --per-ip-conn-cap 300

# اگر UFW/firewalld فعال است و با آگاهی می‌خواهید ادامه دهید
sudo ./abuse-guard.sh install --lockdown --force

# کنترل دستی کامل (بدون auto-detect)
sudo ./abuse-guard.sh install --lockdown --no-auto-detect --xray-ports "443,2053" --panel-ports "54321" --allow-in-udp "51820"

# اگر آگاهانه می‌خواهی با lockdown و فقط auto-detect ادامه بدهی (برای mixed node توصیه نمی‌شود)
sudo ./abuse-guard.sh install --lockdown --allow-unsafe-lockdown-auto

# وضعیت
/usr/local/sbin/abuse-guard status

# اعمال مجدد قوانین (هر بار apply اجرا شود، پورت‌ها دوباره اسکن می‌شوند)
sudo /usr/local/sbin/abuse-guard apply

# حذف کامل
sudo /usr/local/sbin/abuse-guard uninstall
```

## نکته مهم (Reality / Tunnel)

این اسکریپت در لایه شبکه (L3/L4) کار می‌کند و به محتوای TLS/Reality دست نمی‌زند.
اگر `--lockdown` فعال باشد، باید پورت‌های لازم شما (Xray/Panel/UDP tunnel/...) باز باشند.

اگر هر سرور فقط یک سرویس اصلی دارد و همان سرویس موقع install/apply واقعاً در حال listen است،
و `status` نشان می‌دهد دقیقاً یک `auto_detect_families` عمومی دیده شده،
auto-detect جدید از روی listener فعال همان سرویس کار می‌کند و از config حدسی امن‌تر است.

در این حالت، panelهای مدیریتی مثل `x-ui/3x-ui` به‌صورت پیش‌فرض auto-allow نمی‌شوند؛
اگر واقعاً لازم است public بمانند، باید یا دستی در manifest/`--panel-ports` بدهی یا `--auto-allow-panels` را آگاهانه فعال کنی.

اگر سرور mixed است، یا سرویس هنوز بالا نیامده، یا قبل از deploy می‌خواهی lockdown بزنی،
روش پیشنهادی این است که به auto-detect تکیه نکنی و listenerهای واقعی TCP/UDP را در فایل manifest صریح بدهی.

نمونه فایل: [listeners.example.conf](./listeners.example.conf)
در زمان install، این فایل داخل `/etc/abuse-guard/listeners.conf` کپی می‌شود تا systemd هم همیشه همان را بخواند.

فرمت:
```text
tcp 443 xray-shared
udp 51820 wireguard
both 8443 hysteria2
```

## چه چیزهایی را کم می‌کند؟

- بلاک خروجی SMTP برای کاهش اسپم ایمیل
- بلاک خروجی BitTorrent (پورت‌های رایج + در iptables تشخیص signature)
- بلاک amplificationهای رایج (DNS/NTP/SSDP/Memcached)
- rate limitهای ورودی/خروجی اختیاری برای کاهش abuse

نکته: در backend `nft` تشخیص DPI بیت‌تورنت وجود ندارد و فقط بلاک مبتنی بر پورت اعمال می‌شود.

نکته مهم: limitهای عمومی TCP به‌صورت پیش‌فرض غیرفعال‌اند، چون روی workloadهای VPN/Proxy/Tunnel می‌توانند
به‌سادگی باعث اختلال شوند. اگر لازم دارید، فقط بعد از تست روی ترافیک واقعی و با مقادیر محافظه‌کارانه فعال‌شان کنید.

همچنین `nf_conntrack_max` دیگر به‌صورت عدد ثابت تنظیم نمی‌شود؛ مقدار مناسب آن به RAM و الگوی ترافیک واقعی بستگی دارد.

اگر mixed public node دارید، `--listeners-file` از `auto-detect` امن‌تر است.
اگر هر سرور single-service است، auto-detect زمانی قابل اتکاتر است که listener فعال همان سرویس در `ss` دیده شود.
اگر پورت‌های سرویس اصلی دائماً عوض می‌شوند، auto-detect برای خود سرویس اصلی مناسب‌تر از پورت ثابت است؛
اما پورت‌های مدیریت و admin را بهتر است auto-open نکنید مگر عمداً.

اگر از `iptables-persistent`/`netfilter-persistent` استفاده می‌کنید، قوانین abuse-guard را داخل snapshot ذخیره نکنید؛
در غیر این صورت بعد از uninstall ممکن است قوانین قدیمی از فایل persistent دوباره لود شوند.

یادآوری: حفاظت واقعی DDoS عمدتاً سمت دیتاسنتر/پرووایدر است؛ این ابزار «baseline hardening» است.
