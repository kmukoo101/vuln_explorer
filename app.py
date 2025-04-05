import streamlit as st
import pandas as pd
import requests
import logging
import altair as alt
import re
from collections import Counter
from wordcloud import WordCloud
import matplotlib.pyplot as plt

# Configure Streamlit page
st.set_page_config(page_title="Vuln Explorer", layout="wide")

st.title("Vuln Explorer")
st.caption("Explore real-world vulnerabilities with filters, insights, and clarity.")

# --- LOGGING SETUP ---
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

# --- DATA LOADING FUNCTION ---
@st.cache_data(show_spinner=True)
def load_data():
    """Fetches CVE data from the NVD API and returns it as a DataFrame."""
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
            published = item["cve"].get("published", "N/A")
            vector = "N/A"
            score = "N/A"
            if "cvssMetricV31" in metrics:
                score = metrics["cvssMetricV31"][0]["cvssData"].get("baseScore", "N/A")
                vector = metrics["cvssMetricV31"][0]["cvssData"].get("vectorString", "N/A")
            elif "cvssMetricV2" in metrics:
                score = metrics["cvssMetricV2"][0]["cvssData"].get("baseScore", "N/A")
                vector = metrics["cvssMetricV2"][0]["cvssData"].get("vectorString", "N/A")

            cves.append({
                "CVE ID": cve_id,
                "Description": description,
                "CVSS Score": score,
                "Published": published,
                "CVSS Vector": vector
            })
        return pd.DataFrame(cves)
    except Exception as e:
        logger.error(f"Failed to load data: {e}")
        return pd.DataFrame(columns=["CVE ID", "Description", "CVSS Score", "Published", "CVSS Vector"])

# --- LOAD DATA INTO MEMORY ---
df = load_data()

# --- SIDEBAR FILTERS ---
st.sidebar.title("Filters")
min_score, max_score = st.sidebar.slider("CVSS Score Range", 0.0, 10.0, (0.0, 10.0), 0.1)
search_term = st.sidebar.text_input("Search CVEs by keyword")
preset = st.sidebar.selectbox("Preset filters", ["None", "Critical only", "Buffer Overflow", "OpenSSL"])

# --- FILTER FUNCTION ---
def score_filter(val):
    """Checks if score is within slider range."""
    try:
        return min_score <= float(val) <= max_score
    except:
        return False

filtered_df = df[df["CVSS Score"].apply(score_filter)]

if search_term:
    filtered_df = filtered_df[filtered_df["Description"].str.contains(search_term, case=False, na=False)]

if preset == "Critical only":
    filtered_df = filtered_df[filtered_df["CVSS Score"].apply(lambda x: float(x) >= 9 if x != "N/A" else False)]
elif preset == "Buffer Overflow":
    filtered_df = filtered_df[filtered_df["Description"].str.contains("buffer overflow", case=False, na=False)]
elif preset == "OpenSSL":
    filtered_df = filtered_df[filtered_df["Description"].str.contains("openssl", case=False, na=False)]

# --- FORMAT CVSS SCORES FOR DISPLAY ---
filtered_df["CVSS Score"] = filtered_df["CVSS Score"].apply(
    lambda x: f"{float(x):.1f}" if x != "N/A" else x
)

# --- ADD SEVERITY LABELS ---
def get_severity(score):
    """Classifies CVSS score into severity categories."""
    try:
        score = float(score)
        if score < 4.0:
            return "Low"
        elif score < 7.0:
            return "Medium"
        elif score < 9.0:
            return "High"
        else:
            return "Critical"
    except:
        return "N/A"

filtered_df["Severity"] = filtered_df["CVSS Score"].apply(get_severity)

# --- FEATURED CVE ---
st.subheader("Featured CVE")
if not filtered_df.empty:
    featured = filtered_df.sort_values(by="CVSS Score", ascending=False).iloc[0]
    st.markdown(f"**{featured['CVE ID']}**  ")
    st.markdown(f"*Severity:* {featured['Severity']} | *Score:* {featured['CVSS Score']}  ")
    st.markdown(f"**Vector:** {featured['CVSS Vector']}  ")
    st.markdown(f"{featured['Description']}")

# --- CVSS SCORE DISTRIBUTION CHART ---
st.subheader("CVSS Score Distribution")
chart_data = filtered_df[filtered_df["CVSS Score"] != "N/A"].copy()
chart_data["CVSS Score"] = chart_data["CVSS Score"].astype(float)
hist = alt.Chart(chart_data).mark_bar().encode(
    alt.X("CVSS Score:Q", bin=alt.Bin(maxbins=10)),
    y='count()',
    tooltip=["count()"]
).properties(height=200)

st.altair_chart(hist, use_container_width=True)

# --- SEVERITY BREAKDOWN PIE CHART ---
st.subheader("Severity Breakdown")
severity_counts = filtered_df["Severity"].value_counts().reset_index()
severity_counts.columns = ["Severity", "Count"]
pie_chart = alt.Chart(severity_counts).mark_arc().encode(
    theta="Count:Q",
    color="Severity:N",
    tooltip=["Severity", "Count"]
).properties(height=250)

st.altair_chart(pie_chart, use_container_width=True)

# --- TIMELINE CHART OF PUBLISHED DATES ---
st.subheader("Published Timeline")
timeline_data = chart_data.copy()
timeline_data["Published"] = pd.to_datetime(timeline_data["Published"], errors='coerce')
timeline = alt.Chart(timeline_data.dropna()).mark_bar().encode(
    x=alt.X("yearmonth(Published):T", title="Month"),
    y='count()',
    tooltip=["count()"]
).properties(height=200)

st.altair_chart(timeline, use_container_width=True)

# --- TOP CVEs SECTION ---
st.subheader("Top Critical CVEs")
top_cves = chart_data.sort_values(by="CVSS Score", ascending=False).head(5)
for _, row in top_cves.iterrows():
    st.markdown(f"- {row['CVE ID']} — {row['Description'][:100]}... (Score: {row['CVSS Score']})")

# --- WORDCLOUD ---
st.subheader("Common Terms")
words = ' '.join(filtered_df["Description"].dropna()).lower()
wordcloud = WordCloud(width=800, height=300, background_color='white').generate(words)
fig, ax = plt.subplots(figsize=(10, 3))
ax.imshow(wordcloud, interpolation='bilinear')
ax.axis('off')
st.pyplot(fig)

# --- MAIN TABLE DISPLAY ---
st.subheader("Filtered CVEs")
st.write(f"Found {len(filtered_df)} vulnerabilities within the selected filters.")

# --- DOWNLOAD CSV BUTTON ---
@st.cache_data
def convert_df(df):
    """Converts a DataFrame to CSV bytes."""
    return df.to_csv(index=False).encode('utf-8')

csv = convert_df(filtered_df)
st.download_button("Download CSV", csv, "filtered_cves.csv", "text/csv")

# --- DISPLAY FILTERED CVEs TABLE ---
st.dataframe(filtered_df.sort_values(by="CVSS Score", ascending=False), use_container_width=True)

# --- COPYABLE CVE ID LIST ---
with st.expander("Copy All CVE IDs"):
    st.code('\n'.join(filtered_df['CVE ID'].tolist()), language='text')

# --- EXPANDER FOR FULL DESCRIPTIONS ---
with st.expander("Full Descriptions", expanded=False):
    for _, row in filtered_df.iterrows():
        st.markdown(f"**{row['CVE ID']}** — {row['Description']}")

# --- CVSS VECTORS ---
with st.expander("CVSS Vectors", expanded=False):
    for _, row in filtered_df.iterrows():
        st.markdown(f"**{row['CVE ID']}**: {row['CVSS Vector']}")

# --- CVSS HELP ---
with st.expander("What does the CVSS vector mean?"):
    st.markdown("""
    - **AV**: Attack Vector (e.g., Network, Adjacent, Local)
    - **AC**: Attack Complexity
    - **PR**: Privileges Required
    - **UI**: User Interaction
    - **S**: Scope
    - **C/I/A**: Confidentiality / Integrity / Availability Impact
    [Read more on CVSS](https://nvd.nist.gov/vuln-metrics/cvss)
    """)

# --- USER FEEDBACK ---
st.markdown("---")
st.subheader("Feedback")
st.text_area("What would you like to see in the next version?", key="feedback")

# --- FOOTER ---
st.markdown("""
---
Built with simplicity, reusability, and clarity in mind. If something breaks, you'll know why.
""")
