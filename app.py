
import streamlit as st

from detector import analyze_url, analyze_email


st.set_page_config(
    page_title="PhishGuard",
    page_icon="🛡️",
    layout="centered",
)

st.title("🛡️ PhishGuard")
st.caption("A Python-based phishing indicator analysis tool")

st.info(
    "PhishGuard uses heuristic rules to identify warning signs. "
    "Its scores are not probabilities or definitive verdicts."
)

url_tab, email_tab = st.tabs(
    ["🔗 URL Analysis", "📧 Email Analysis"]
)


def display_results(score, findings, assessment):
    st.metric("Risk Score", f"{score}/100")
    st.subheader(f"Assessment: {assessment}")
    st.progress(score / 100)

    st.subheader("Findings")

    for finding in findings:
        st.write(f"• {finding}")

    st.caption(
        "A low-risk result does not guarantee safety. "
        "Review suspicious links independently. "
        "PhishGuard does not automatically visit submitted URLs."
    )


with url_tab:
    st.subheader("Analyze a URL")

    url = st.text_input(
        "Enter a URL",
        placeholder="https://example.com",
        key="url_input",
    )

    if st.button("Analyze URL", key="analyze_url_button"):
        if not url.strip():
            st.warning("Please enter a URL first.")
        else:
            score, findings, assessment = analyze_url(url)
            display_results(score, findings, assessment)


with email_tab:
    st.subheader("Analyze Email Text")

    email = st.text_area(
        "Paste the email message",
        placeholder="Paste the email text here...",
        height=220,
        key="email_input",
    )

    if st.button("Analyze Email", key="analyze_email_button"):
        if not email.strip():
            st.warning("Please paste email text first.")
        else:
            score, findings, assessment = analyze_email(email)
            display_results(score, findings, assessment)
