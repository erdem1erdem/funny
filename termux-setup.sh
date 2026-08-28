#!/data/data/com.termux/files/usr/bin/bash
# WiFi Killer - Terminal kurulum scripti (Termux + Linux/WSL)
# Kullanim:  bash termux-setup.sh
#
# NOT: ARP spoofing (internet kesme / yonlendirme) icin ROOT gerekir.
# Root'suz sadece tarama ve trafik izleme gibi pasif ozellikler calisir.
# UYARI: WSL icinde ARP spoofing CALISMAZ (WSL, ana makinenin WiFi kartina
# ham paket erisimi saglayamaz). Bunun icin gercek Linux live USB veya Termux+root gerekir.

set -e

echo "=== WiFi Killer Kurulumu ==="
echo

# --- Ortam algilama ---
if [ -d "/data/data/com.termux/files/usr" ]; then
    ENV_NAME="termux"
elif grep -qi "microsoft" /proc/version 2>/dev/null; then
    ENV_NAME="wsl"
else
    ENV_NAME="linux"
fi
echo "[i] Algilanan ortam: $ENV_NAME"
echo

# --- Sistem paketleri ---
if [ "$ENV_NAME" = "termux" ]; then
    echo "[1/4] Termux temel paketleri kuruluyor..."
    pkg update -y
    pkg install -y python python-pip iproute2 util-linux net-tools libpcap \
        openssl ndk-sysroot clang make libffi || {
            echo "[!] Bazi paketler kurulamadi. Asagidakileri tek tek deneyin:"
            echo "    pkg install python iproute2 libpcap"
        }
else
    echo "[1/4] Linux (apt) temel paketleri kuruluyor..."
    if command -v apt-get >/dev/null 2>&1; then
        sudo apt-get update -y
        sudo apt-get install -y python3 python3-venv python3-pip python3-scapy \
            python3-netaddr iproute2 iputils-ping net-tools libpcap0.8 \
            openssl libssl-dev build-essential libffi-dev tcpdump || {
                echo "[!] Bazi apt paketleri kurulamadi. Tek tek deneyin."
            }
    else
        echo "[!] apt-get bulunamadi. Bu script Debian/Ubuntu tabanli sistemler icindir."
    fi
fi

# --- Python ortami: PEP 668'i asmak icin sanal ortam (venv) kullan ---
VENV_DIR=".venv"
echo "[2/4] Python sanal ortami ($VENV_DIR) ve bagimliliklari hazirlaniyor..."
if [ "$ENV_NAME" = "termux" ]; then
    # Termux'ta Python dogrudan kurulabilir (pip ayrıca yukseltilmez)
    python -m pip install scapy netaddr cryptography
else
    # Debian/Ubuntu: sistem Python'ina pip YASAK (PEP 668). venv sart.
    if [ ! -d "$VENV_DIR" ]; then
        python3 -m venv "$VENV_DIR"
    fi
    "$VENV_DIR/bin/pip" install --upgrade pip >/dev/null 2>&1 || true
    "$VENV_DIR/bin/pip" install scapy netaddr cryptography
fi

echo "[3/4] Proje betigi hazirlaniyor..."
chmod +x main.py diagnose.py 2>/dev/null || true

echo "[4/4] Root / WSL durumu kontrol ediliyor..."
if [ "$ENV_NAME" = "wsl" ]; then
    echo "  [x] WSL algilandi: ARP spoofing BU ORTAMDA CALISMAZ."
    echo "      WSL, ana makinenin WiFi kartina ham paket erisimi saglayamaz."
    echo "      Tam islev icin Termux + root veya gercek Linux live USB kullanin."
    echo "      Sadece tarama/izleme (pasif) denenebilir."
elif command -v su >/dev/null 2>&1 && su -c 'echo ok' >/dev/null 2>&1; then
    echo "  -> Root mevcut: TUM ozellikler kullanilabilir."
    echo "     Calistirma:  su -c '$VENV_DIR/bin/python main.py'"
else
    echo "  -> Root bulunamadi: SADECE tarama/izleme calisir."
    echo "     Kesme/yonlendirme icin root (su) gerekir."
    echo "     Calistirma:  $VENV_DIR/bin/python main.py  (pasif mod)"
fi

echo
echo "=== Kurulum tamam ==="
echo "Calistirma:"
if [ "$ENV_NAME" = "termux" ]; then
    echo "  python main.py"
else
    echo "  $VENV_DIR/bin/python main.py"
fi
