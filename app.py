import streamlit as st
import pandas as pd
import requests
import logging
import altair as alt

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

# --- FORMAT SCORE ---
filtered_df["CVSS Score"] = filtered_df["CVSS Score"].apply(
    lambda x: f"{float(x):.1f}" if x != "N/A" else x
)

# --- CHART ---
st.subheader("CVSS Score Distribution")
chart_data = filtered_df[filtered_df["CVSS Score"] != "N/A"].copy()
chart_data["CVSS Score"] = chart_data["CVSS Score"].astype(float)
hist = alt.Chart(chart_data).mark_bar().encode(
    alt.X("CVSS Score:Q", bin=alt.Bin(maxbins=10)),
    y='count()',
    tooltip=["count()"]
).properties(height=200)

st.altair_chart(hist, use_container_width=True)

# --- MAIN ---
st.subheader("Filtered CVEs")
st.write(f"Found {len(filtered_df)} vulnerabilities within the selected score range.")

# --- DOWNLOAD BUTTON ---
@st.cache_data
def convert_df(df):
    return df.to_csv(index=False).encode('utf-8')

csv = convert_df(filtered_df)
st.download_button("⬇Download CSV", csv, "filtered_cves.csv", "text/csv")

# --- DATAFRAME ---
st.dataframe(filtered_df.sort_values(by="CVSS Score", ascending=False), use_container_width=True)

# --- EXPANDER FOR FULL DESCRIPTIONS ---
with st.expander("Full Descriptions", expanded=False):
    for _, row in filtered_df.iterrows():
        st.markdown(f"**{row['CVE ID']}** — {row['Description']}")

# --- FOOTER ---
st.markdown("""
---
Built with simplicity, reusability, and clarity in mind. If something breaks, you'll know why. 
""")
