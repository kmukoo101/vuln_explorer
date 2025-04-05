import streamlit as st
import pandas as pd
import requests
import logging
import altair as alt
import re
from collections import Counter

# Configure Streamlit page
st.set_page_config(page_title="Vuln Explorer", layout="wide")

# --- BANNER IMAGE FROM GITHUB ---
st.markdown(
    """
    <style>
        .banner-img {
            text-align: center;
            margin-bottom: 1.5rem;
        }
        .banner-img img {
            max-height: 120px;
            width: auto;
        }
    </style>
    <div class="banner-img">
        <img src="https://raw.githubusercontent.com/kmukoo101/vuln_explorer/main/vuln_explorer.png" alt="Vuln Explorer Logo">
    </div>
    """,
    unsafe_allow_html=True
)

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

# --- CVE COMPARISON TOOL ---
selected_cves = st.sidebar.multiselect("Compare CVEs", filtered_df["CVE ID"].tolist())
if selected_cves:
    st.subheader("CVE Comparison")
    comparison_df = filtered_df[filtered_df["CVE ID"].isin(selected_cves)].set_index("CVE ID")
    st.dataframe(comparison_df, use_container_width=True)

# --- TELL ME A STORY MODE ---
if st.sidebar.button("Show Me Something Interesting"):
    interesting_cve = filtered_df[
        filtered_df["Description"].str.contains(
            "race condition|strange|weird|unusual|timing|sequence", case=False, na=False
        )
    ]
    if not interesting_cve.empty:
        sample = interesting_cve.sample(1).iloc[0]
        st.subheader("CVE Story Highlight")
        st.markdown(f"**{sample['CVE ID']}**")
        st.markdown(f"*Published:* {sample['Published']} | *Score:* {sample['CVSS Score']} | *Vector:* {sample['CVSS Vector']}")
        st.markdown(sample['Description'])
    else:
        st.info("No unusual CVEs found within current filters.")

# --- TREND SUMMARY DASHBOARD ---
trend_terms = ["buffer", "overflow", "denial", "remote", "execute", "privilege", "escalation"]
trend_counts = {term: 0 for term in trend_terms}
for desc in filtered_df["Description"].dropna():
    for term in trend_terms:
        if term in desc.lower():
            trend_counts[term] += 1
trend_df = pd.DataFrame.from_dict(trend_counts, orient='index', columns=["Mentions"])
trend_df.index.name = "Keyword"
st.subheader("Exploit Trend Summary")
st.table(trend_df.sort_values(by="Mentions", ascending=False))

# --- SIMPLIFY CVE DESCRIPTION ---
def simplify_description(text):
    """Performs basic NLP substitutions to make text easier to understand."""
    replacements = {
        "vulnerability": "weak spot",
        "remote code execution": "can run code remotely",
        "privilege escalation": "gain more access",
        "buffer overflow": "exceeds data limits",
        "denial of service": "system crash risk",
    }
    for term, sub in replacements.items():
        text = re.sub(term, sub, text, flags=re.IGNORECASE)
    return text

if not filtered_df.empty:
    st.subheader("Simplified Description")
    st.write(simplify_description(filtered_df.iloc[0]['Description']))

# --- GAMIFIED SEVERITY GUESS ---
with st.expander("Guess That Severity"):
    if not filtered_df.empty:
        sample = filtered_df.sample(1).iloc[0]
        # continue using sample...
    else:
        st.warning("No CVEs available in the current filter to display.")

    st.markdown(f"**Description:** {sample['Description']}")
    user_guess = st.radio("Your guess for the severity:", ["Low", "Medium", "High", "Critical"], key="guess")
    if st.button("Reveal Answer", key="reveal_guess"):
        actual = sample['Severity']
        st.markdown(f"**Actual Severity:** {actual}")
        if user_guess == actual:
            st.success("Correct!")
        else:
            st.warning("Not quite. Keep learning!")

# --- CVSS SCORE DISTRIBUTION CHART ---
st.subheader("CVSS Score Distribution")
score_data = filtered_df[filtered_df["CVSS Score"] != "N/A"].copy()
score_data["CVSS Score"] = score_data["CVSS Score"].astype(float)
hist = alt.Chart(score_data).mark_bar().encode(
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
timeline_data = score_data.copy()
timeline_data["Published"] = pd.to_datetime(timeline_data["Published"], errors='coerce')
timeline = alt.Chart(timeline_data.dropna()).mark_bar().encode(
    x=alt.X("yearmonth(Published):T", title="Month"),
    y='count()',
    tooltip=["count()"]
).properties(height=200)
st.altair_chart(timeline, use_container_width=True)

# --- COMMON TERMS COUNTER ---
st.subheader("Common Terms")
all_words = re.findall(r'\b\w+\b', ' '.join(filtered_df['Description'].dropna()).lower())
stopwords = set(["the", "and", "for", "this", "that", "with", "from", "into", "when", "using", "will", "has"])
filtered_words = [word for word in all_words if word not in stopwords]
common = Counter(filtered_words).most_common(15)
terms_df = pd.DataFrame(common, columns=["Word", "Count"])
st.dataframe(terms_df, use_container_width=True)

# --- DOWNLOAD CSV BUTTON ---
@st.cache_data
def convert_df(df):
    """Converts a DataFrame to CSV bytes."""
    return df.to_csv(index=False).encode('utf-8')

csv = convert_df(filtered_df)
st.download_button("Download CSV", csv, "filtered_cves.csv", "text/csv", key="download_csv_filtered")

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

# --- TOP CVEs SECTION ---
st.subheader("Top Critical CVEs")
top_cves = chart_data.sort_values(by="CVSS Score", ascending=False).head(5)
for _, row in top_cves.iterrows():
    st.markdown(f"- {row['CVE ID']} — {row['Description'][:100]}... (Score: {row['CVSS Score']})")

# --- COMMON TERMS COUNTER ---
st.subheader("Common Terms")
words = ' '.join(filtered_df["Description"].dropna()).lower().split()
common_words = Counter(words).most_common(20)
terms_df = pd.DataFrame(common_words, columns=["Word", "Count"])
st.table(terms_df.style.set_properties(**{"text-align": "left"}).set_table_styles(
    [{"selector": "th", "props": [("text-align", "left")]}]
))

# --- MAIN TABLE DISPLAY ---
st.subheader("Filtered CVEs")
st.write(f"Found {len(filtered_df)} vulnerabilities within the selected filters.")

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
