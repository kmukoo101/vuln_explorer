import streamlit as st
import pandas as pd
import requests
import logging

st.set_page_config(page_title="Vuln Explorer", layout="wide")

st.title("Vuln Explorer")
st.caption("Explore real-world vulnerabilities with filters, insights, and clarity.")

# --- LOGGING ---
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

# --- CACHED DATA LOADER ---
@st.cache_data(show_spinner=True)
def load_data():
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=100"
    try:
        res = requests.get(url, timeout=10)
        res.raise_for_status()
        raw = res.json()
        cves = []
        for item in raw.get("vulnerabilities", []):
            cve_id = item["cve"]["id"]
            description = item["cve"]["descriptions"][0]["value"]
            metrics = item["cve"].get("metrics", {})
            score = "N/A"
            if "cvssMetricV31" in metrics:
                score = metrics["cvssMetricV31"][0]["cvssData"].get("baseScore", "N/A")
            elif "cvssMetricV2" in metrics:
                score = metrics["cvssMetricV2"][0]["cvssData"].get("baseScore", "N/A")

            cves.append({
                "CVE ID": cve_id,
                "Description": description,
                "CVSS Score": score
            })
        return pd.DataFrame(cves)
    except Exception as e:
        logger.error(f"Failed to load data: {e}")
        return pd.DataFrame(columns=["CVE ID", "Description", "CVSS Score"])

# --- LOAD DATA ---
df = load_data()

# --- SIDEBAR ---
st.sidebar.title("Filters")
min_score, max_score = st.sidebar.slider("CVSS Score Range", 0.0, 10.0, (0.0, 10.0), 0.1)

# --- FILTER LOGIC ---
def score_filter(val):
    try:
        return min_score <= float(val) <= max_score
    except:
        return False

filtered_df = df[df["CVSS Score"].apply(score_filter)]

# --- MAIN ---
st.subheader("Filtered CVEs")
st.write(f"Found {len(filtered_df)} vulnerabilities within the selected score range.")
st.dataframe(filtered_df, use_container_width=True)

# --- FOOTER ---
st.markdown("""
---
Built with simplicity, reusability, and clarity in mind. If something breaks, you'll know why. 
""")
