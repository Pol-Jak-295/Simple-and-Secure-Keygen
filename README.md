# Deterministic Ed25519 Key Generator

A simple Python tool to generate **deterministic Ed25519 SSH keys** from a seed string.  
Ideal for experiments, learning, or secure personal key generation.

---

## Features
- Generates **private/public SSH keys** from a seed string  
- Optional password protection for private keys  
- Keys are saved in a `keys/` folder  
- Non-commercial use only; credit required (CC BY-NC 4.0)  

---

## Usage

### Windows
1. Download the standalone `.exe` from the **Release Assets**  
2. Double-click to run the program  

No Python installation required.

### Linux/macOS
1. Ensure Python 3 is installed  
2. Install the `cryptography` library if you don’t have it:

```bash
pip install cryptography
```
