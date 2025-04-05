# Vuln Explorer

An app aimed to help you explore real-world CVEs using data pulled directly from the [NVD API](https://nvd.nist.gov/developers) by filtering vulnerabilities by CVSS score and presenting them in a clean, easy-to-read format.

## Features

- Pulls live CVE data from NIST's NVD API
- Filters vulnerabilities by CVSS base score
- Simple, visual UI built with Streamlit
- Designed with clarity, modularity, and reliability in mind

## Why? -Why Not?

> Our biggest weakness is what we don't know.  
> Vuln Explorer helps make threat intelligence visible, fast.

## Quick Start

### 1. Install requirements
```bash
pip install -r requirements.txt
```

### 2. Run the app
```bash
streamlit run app.py
```

---

## Requirements

- Python 3.9+
- Streamlit
- Pandas
- Requests

```txt
streamlit>=1.30
pandas>=2.0
requests>=2.31
```
