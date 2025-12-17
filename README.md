# FTP-SNIFF

Simple **FTP packet sniffer** written in **Python**.
It captures FTP usernames and passwords from network traffic to show why FTP is insecure.

⚠️ **Educational use only. Do not use without permission.**

---

## Features

* Sniffs FTP traffic (port 21)
* Captures `USER` and `PASS` commands
* Shows credentials in terminal
* Lightweight and beginner‑friendly

---

## Requirements

* Python 3
* Scapy

```bash
pip install scapy
```

---

## Usage

```bash
git clone https://github.com/zen1557/FTP-SNIFF.git
cd FTP-SNIFF
sudo python3 ftpsniffer.py -i eth0
```

Replace `eth0` with your network interface.

---

## Example Output

```text
FTP Login Detected
User: admin
Password: 123456
```

---

## Disclaimer

This project is for **learning and ethical testing only**.
Unauthorized sniffing is illegal.

---

## License

MIT License

---

## Author

**zen1557**
[https://github.com/zen1557](https://github.com/zen1557)

⭐ Star the repo if you like it
