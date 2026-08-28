# WiFi Killer

Android (Termux) ve Windows'ta calisabilen, yerel agdaki cihazlari tespit edip
ARP spoofing ile internetlerini kesen / yonlendiren bir araç.

> **Önemli uyarı:** Bu yalnızca kendi ağınızda ve yasal olarak yetkiniz olan
> cihazlarda test amaciyla kullanilmalidir.

## Termux kurulumu

Termux'ta proje dizinini telefonunuza alin (ornegin `~/wifi-killer`), sonra:

```bash
cd ~/wifi-killer
bash termux-setup.sh
```

Script Python bagimliliklarini (scapy, netaddr, cryptography) ve gerekli
paketleri otomatik kurar.

## ROOT (su) Gerekliliği

- **İnternet kesme / URL'ye yonlendirme (ARP spoofing)** ancak **root** ile
  calisir. Android çekirdeği ham paket gonderimi (raw socket) ve arayüzun
  promiscuous moda alinmasini yalnizca root'a izin verir.
- **Root'suz** sadece pasif ozellikler calisir:
  - Ağ tarama ve cihaz listeleme
  - Kimlik tespiti (mDNS / SSDP / DHCP / port/OS tahmini)
  - DNS / SNI / HTTP trafik izleme

### Root varsa

```bash
su -c 'cd ~/wifi-killer && python main.py'
```

### Root yoksa

```bash
python main.py
```

Program pasif modda calisir; kesme islemlerinde root uyarisi ve yonlendirme
hatasi alirsiniz.

## Kullanim

- `main.py`  : metin menulu arayuz (satir 1-11 arasi secenekler)
- `tui_app.py`: alternatif grafik (Textual) arayuz
- `diagnose.py <hedef_ip>`: sorun giderme aci (sinirli)

## Kurulum notlari (Termux'ta)

- Telefonunuzun WiFi baglantisinin dogru arayuzu kullandigindan emin olun;
  bazi cihazlar/ayarlar paket yonlendirmeyi kisitlayabilir.
- `set_forwarding` (Internet açık kalarak izleme) Linux'ta
  `/proc/sys/net/ipv4/ip_forward` dosyasini yazar; bunun icin de root gerekir.

## Windows kurulumu

- [Npcap](https://npcap.com) kurun (WinPcap degil).
- `pip install -r requirements.txt`
- Yonetici olarak `python main.py`

## Yasal uyari

Bu araç yalnizca sahibi olduğunuz veya test izni aldığınız ağlarda kullanin.
İzinsiz aglara mudahale birçok ulkede suc tur.
