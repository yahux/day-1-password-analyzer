# 🔐 Password Strength Analyzer (Cybersecurity Tool)

A Python-based CLI cybersecurity tool that analyzes password strength using entropy, character sets, and brute-force crack time estimation.

---

## 🚀 Features

- Password entropy calculation
- Character set detection (lowercase, uppercase, numbers, symbols)
- Estimated brute-force crack time
- Password strength classification
- Smart security feedback system
- CLI with colored output (red/yellow/green)

---

## 🧠 How It Works

The tool analyzes password strength using:

- Entropy formula: Entropy = length × log2(charset_size)


- Brute-force estimation:
Assumes 10 billion guesses per second

---

## 📦 Project Structure
password-analyzer/
│── main.py
│── analyzer.py
│── utils.py
│── requirements.txt
│── README.md


---

## ▶️ How to Run

```bash
pip install -r requirements.txt
python main.py