# Sandbox Project Using REMnux (Offline)

This project was developed as part of an internship at **NFC (Nuclear Fuel Complex)**.  
It demonstrates a secure sandbox environment built using **REMnux** and designed to operate **completely offline** — ideal for malware and file behavior analysis in a controlled environment.

---

## 🧠 Overview
The sandbox system performs both **Static** and **Dynamic** analysis of uploaded files.  
It supports execution in **Windows (host)** and **REMnux VM (guest)** environments, allowing safe inspection of potentially malicious samples.

---

## ✨ Features
- Upload and analyze files securely through a web interface  
- Perform both **Static** and **Dynamic** malware analysis  
- Generate detailed **Excel reports** summarizing findings  
- Works **fully offline** (no internet connection required)  
- Compatible with both **Windows** and **VMware/REMnux** setups  
- Clean, modular backend structure using Flask  
- Supports exporting results for further manual inspection

---

## 🧰 Tech Stack
- **Python (Flask)** — Web framework  
- **REMnux** — Analysis environment (Linux-based forensic toolkit)  
- **openpyxl** — Excel report generation  
- **hashlib, os, json** — File handling and hashing utilities  
- **Gunicorn / Apache (optional)** — For production deployment

---
