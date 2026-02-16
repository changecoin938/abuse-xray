# abuse-guard

اسکریپت یک‌کلیکی برای کاهش abuse report روی سرورهای عمومی VPN/Proxy (مثل Xray/X-UI).

## نصب سریع (پیشنهادی)

```bash
# روش سازگارتر (بدون process substitution)
curl -fsSL https://raw.githubusercontent.com/changecoin938/abuse-xray/main/abuse-guard.sh | sudo bash -s -- install --lockdown
```

اگر خودتان `root` هستید:

```bash
curl -fsSL https://raw.githubusercontent.com/changecoin938/abuse-xray/main/abuse-guard.sh | bash -s -- install --lockdown
```

اگر با خطای `/dev/fd/*` مواجه شدید، علتش این است که `sudo bash <(curl ...)` روی بعضی سرورها FDها را می‌بندد.

## دستورات

```bash
# نصب (auto-detect پورت‌ها فعال است)
sudo ./abuse-guard.sh install --lockdown

# اگر می‌خواهید fallback اسکن عمومی ss هم مجاز باشد (در lockdown ریسک باز شدن پورت‌های اضافی دارد)
sudo ./abuse-guard.sh install --lockdown --allow-ss-fallback

# رفرش خودکار قوانین هر 5 دقیقه (پیش‌فرض)، یا مقدار دلخواه
sudo ./abuse-guard.sh install --lockdown --refresh-interval 300

# غیرفعال‌کردن رفرش دوره‌ای
sudo ./abuse-guard.sh install --lockdown --refresh-interval 0

# اگر UFW/firewalld فعال است و با آگاهی می‌خواهید ادامه دهید
sudo ./abuse-guard.sh install --lockdown --force

# کنترل دستی کامل (بدون auto-detect)
sudo ./abuse-guard.sh install --lockdown --no-auto-detect --xray-ports "443,2053" --panel-ports "54321" --allow-in-udp "51820"

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

## چه چیزهایی را کم می‌کند؟

- بلاک خروجی SMTP برای کاهش اسپم ایمیل
- بلاک خروجی BitTorrent (پورت‌های رایج + در iptables تشخیص signature)
- بلاک amplificationهای رایج (DNS/NTP/SSDP/Memcached)
- rate limitهای ورودی/خروجی برای کاهش abuse

نکته: در backend `nft` تشخیص DPI بیت‌تورنت وجود ندارد و فقط بلاک مبتنی بر پورت اعمال می‌شود.

اگر از `iptables-persistent`/`netfilter-persistent` استفاده می‌کنید، قوانین abuse-guard را داخل snapshot ذخیره نکنید؛
در غیر این صورت بعد از uninstall ممکن است قوانین قدیمی از فایل persistent دوباره لود شوند.

یادآوری: حفاظت واقعی DDoS عمدتاً سمت دیتاسنتر/پرووایدر است؛ این ابزار «baseline hardening» است.
