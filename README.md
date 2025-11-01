# 🛰️ WIPER PRO — Defensive / Educational Wi-Fi Monitor Suite
**Version:** v4.2 (Stable Clean Edition)  
**Author:** Muhammad Shahrukh  
**Mode:** Defensive | Educational | Non-offensive  
**License:** MIT-style (Educational Use Only)

---

## ⚙️ Overview
**WIPER PRO** ایک دفاعی (Defensive) Wi-Fi anomaly monitor ہے جو  
Beacon Floods، Rogue APs، اور Management anomalies کو detect کرتا ہے۔  
یہ ٹول صرف **تعلیمی و ethical security** کے لیے بنایا گیا ہے۔

---

## ✨ Features
- Auto monitor mode setup & restore  
- Real-time passive Wi-Fi scan  
- Offline PCAP analysis (Scapy-based)  
- Beacon flood / anomaly detection  
- Safe exit with auto cleanup  
- Lightweight Bash + Python integration  

---

## 🧰 Requirements
- `python3`, `scapy`, `iw`, `ip`, `airmon-ng`, `tcpdump`, `airodump-ng`  
> اگر کچھ tools نہ ہوں تو بھی offline analysis کام کرے گا۔

---

## 🚀 Usage
```bash
chmod +x wiper_defensive_launcher.sh
./wiper_defensive_launcher.sh
