# ALINOSNET - Huawei ONT Master Toolkit v2.0 Pro (by SkydashNET)

Toolkit All-in-One GUI untuk flashing, unlocking Telnet, dan provisi massal ONT Huawei EG8145V5 / HG8145V5 / seri R019-R023 dengan konfigurasi **100% Kebal Reset Fisik**.
Dikembangkan dan ditandatangani digital oleh **SkydashNET** khusus untuk operasional **ALINOSNET**.

---

## 📂 Struktur Direktori

```
Huawei Tools - ALINOSNET/
│
├── 📂 build/                       <── [TEMPAT APLIKASI UTAMA]
│   ├── ALINOS-FlashTool.exe        <── ★ SATU-SATUNYA APLIKASI YANG DIBUKA
│   └── alinos_flashtool.ini        <── File config default bawaan GUI
│
├── 📂 firmware/                    <── [FILE FIRMWARE & XML WAJIB YANG DIPAKAI]
│   ├── R020.bin                    <── Paket Flash Step 1 (Aktifkan Telnet & Equipment)
│   ├── R022.bin                    <── Paket Flash Shell inject khusus modem di versi R022
│   ├── Permanen.bin                <── Paket Flash Step 3a (Unlock Shell China Mode)
│   ├── Preset.bin                  <── Paket Flash Step 3b (Reset Boardinfo ke COMMON)
│   ├── permanen_pwd.bin            <── Paket Flash alternatif (Show plaintext password)
│   ├── HG8145V5-R020-212.bin       <── Stock/Downgrade Firmware R020 untuk seri HG
│   ├── EG8145V5-R021-210.bin       <── Stock/Downgrade Firmware R021 untuk seri EG
│   ├── Config-R021-ALINOSNET-PERMANEN.xml  <── XML Custom ALINOSNET (Auto XPON/GPON/EPON)
│   ├── Config-Default-Remote-WAN.xml       <── XML Clean Slate (Reset WAN lama)
│   ├── 2Config-DEFAULT.xml                 <── XML Default Telkom Clean
│   └── EG8145V5V500R019C10SPC310_common_all.bin <── Stock Firmware Resmi Huawei Common All
│
├── 📂 src/                         <── [SOURCE CODE C]
│   ├── gui/                        <── Source Code GUI (alinos_flashtool.c, .rc, .ico, manifest)
│   └── core/                       <── Core Modules (hwnp.c, flasher.c, telnet.c)
│
├── 📂 Docs/                        <── [ARSIP BAHAN LAMA KOMUNITAS - TIDAK PERLU DIBUKA]
│   └── Bahan Eksekusi/             <── Script .bat, .vbs, dan tool flasher lama
│
├── Makefile                        <── Script compile Linux / Cross-compile Windows
├── build.bat                       <── Script compile 1-klik di Windows
└── README.md                       <── Panduan ini
```

---

## 📌 PANDUAN PENGGUNAAN TEKNISI

### Cukup Buka 1 File Saja:
👉 **`build/ALINOS-FlashTool.exe`**

Tidak perlu buka file bat, vbs, atau tools lain. Semua fungsi sudah terintegrasi:
- **Auto-Discovery Network Adapter**: Dropdown pintar mendeteksi kartu LAN yang terhubung ke modem secara otomatis. Tidak perlu mematikan WiFi laptop! Dilengkapi tombol `Scan` untuk refresh adapter.
- **Live ONT Telemetry Monitor**: Indikator real-time mendeteksi status fisik ONT (`[ONLINE]`, `[IDLE]`, `[RESCUE]`), MAC address hardware via ARP, serta status port Web (HTTP) & Telnet.
- **Built-in UDP Flasher**: Port 4891 subnet broadcast + directed local broadcast (tanpa perlu tool flasher lama).
- **Automated Telnet**: Port 23 login otomatis (`root` / `admin`).
- **100% Kebal Reset Fisik**: Kloning otomatis ke `/mnt/jffs2/hw_default_ctree.xml` dan boardinfo `0x00000001` & `0x00000059`.

---

## 🚀 Alur Kerja di Aplikasi GUI:

1. **Upload XML Awal**:
   - Di web GUI modem (`http://192.168.100.1`), upload `firmware/Config-R021-ALINOSNET-PERMANEN.xml`.
2. **Buka `build/ALINOS-FlashTool.exe`**:
   - **Step 1**: Klik `Flash R020`. Selesai 1 pass, restart power modem.
   - **Step 2**: Klik `Jalankan Step 2` (EquipMode ON + Restore HW). Tunggu modem reboot.
   - **Step 3**: Klik `Flash` Permanen.bin lalu Preset.bin.
   - **Step 4**: Pilih mode di Dropdown (XPON / GPON / EPON / LAN-WAN), klik `Jalankan Step 4`. Otomatis mengunci NVRAM `hw_boardinfo` serta membersihkan file pemicu Optical Blinking GPON.
   - **Step 5**: Isi nama WiFi, Password, akun PPPoE & TR-069, klik `Terapkan Provisioning`.
   - **Step 6**: Tanam Branding (`Custom Info`) & ubah tema web ONT:
     - `Web Merah (Downgrade)`: Buka mode engineering Huawei dan unlock proteksi batas downgrade firmware.
     - `Web Biru (Smart XGPON)`: Web interface modern Smart XGPON dengan menu WAN dan WiFi password show.
   *(Atau klik tombol **`[ START FULL RUN AUTO ]`** untuk menjalankan urutan secara otomatis!)*
3. **Selesai!** Modem siap dipasang di rumah pelanggan dan kebal reset pabrik.

---

## 🔄 Prosedur Khusus: Downgrade Firmware Tinggi (R021 / R022 / R023)
Jika modem terkunci provider dengan firmware versi tinggi dan tidak ada menu Software Upgrade / WAN:
1. Upload `firmware/2Config-DEFAULT.xml` di menu Update Config web modem (`telecomadmin` / `admintelecom`).
2. Di aplikasi ALINOS-FlashTool, di **Step 1** pilih file `firmware/R022.bin` (jika firmware R022) atau `firmware/R020.bin`, lalu klik **Flash**. Power cycle modem setelah lampu indikator naik.
3. Di **Step 6**, klik tombol **`Web Merah (Downgrade)`**. Modem akan reboot.
4. Buka web GUI (`192.168.100.1`), tampilan sekarang berubah menjadi **MERAH (Huawei Engineering)** dan menu **Software Upgrade** terbuka.
5. Upload file firmware target di halaman web Software Upgrade:
   - Seri HG8145V5: `firmware/HG8145V5-R020-212.bin`
   - Seri EG8145V5: `firmware/EG8145V5-R021-210.bin` atau `EG8145V5V500R019C10SPC310_common_all.bin`
6. Setelah reboot, lanjutkan **Step 2**, **Step 3**, **Step 4** (kunci PON mode permanen), dan di **Step 6** klik **`Web Biru (Smart XGPON)`** untuk mengembalikan tampilan web ke tema Biru modern dengan menu WAN lengkap!
