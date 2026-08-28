#!/data/data/com.termux/files/usr/bin/bash
# WiFi Killer - Termux kurulum scripti
# Kullanim:  bash termux-setup.sh
#
# NOT: ARP spoofing (internet kesme / yonlendirme) icin ROOT gerekir.
# Root'suz sadece tarama ve trafik izleme gibi pasif ozellikler calisir.

set -e

echo "=== WiFi Killer Termux Kurulumu ==="
echo

echo "[1/4] Termux temel paketleri kuruluyor..."
pkg update -y
pkg install -y python python-pip iproute2 util-linux net-tools libpcap \
    openssl ndk-sysroot clang make libffi || {
        echo "[!] Bazi paketler kurulamadi. Asagidakileri tek tek deneyin:"
        echo "    pkg install python iproute2 libpcap"
    }

echo "[2/4] Python bagimliliklari kuruluyor..."
# NOT: Termux'ta 'pip install --upgrade pip' YASAK ('python-pip' paketi pip'i
# yonettigi icin). Bu yuzden pip'i ayri yukseltmiyoruz.
python -m pip install scapy netaddr cryptography

echo "[3/4] Proje betigi hazirlaniyor..."
chmod +x main.py diagnose.py 2>/dev/null || true

echo "[4/4] Root durumu kontrol ediliyor..."
if command -v su >/dev/null 2>&1 && su -c 'echo ok' >/dev/null 2>&1; then
    echo "  -> Root mevcut: TUM ozellikler kullanilabilir."
    echo "     Calistirma:  su -c 'python main.py'"
else
    echo "  -> Root bulunamadi: SADECE tarama/izleme calisir."
    echo "     Kesme/yonlendirme icin root (su) gerekir."
    echo "     Calistirma:  python main.py  (pasif mod)"
fi

echo
echo "=== Kurulum tamam ==="
echo "Oneriler:"
echo "  - Telefonunuzun WiFi'ini 'karma' (mixed) moda alin."
echo "  - root ile:   su -c 'cd ~/wifi-killer && python main.py'"
echo "  - kesmesiz:   cd ~/wifi-killer && python main.py"
