import streamlit as st
import os
import sys
import logging
import threading
import time
import pandas as pd
import queue
from logging.handlers import QueueHandler

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

try:
    from spectre import WebCrawler, SecurityReportGenerator
except ImportError:
    st.error("Error: Could not find the 'spectre.py' file. Please make sure it's in the same directory as this UI script.")
    st.stop()

# --- Page Configuration and Custom Styling ---
st.set_page_config(page_title="Spectre UI", layout="wide", initial_sidebar_state="expanded")

MODERN_TERMINAL_THEME = """
<style>
    /* Use Consolas font throughout the app */
    @import url('https://fonts.googleapis.com/css?family=Consolas');
    html, body, [class*="st-"] {
        font-family: 'Consolas', 'Menlo', 'Courier New', monospace;
    }

    /* Main app background and text color */
    .stApp {
        background-color: #1e1e1e;
        color: #F1F1F1;
    }

    /* --- Sidebar Styling --- */
    [data-testid="stSidebar"] {
        background-color: #181818;
        border-right: 1px solid #2ecc71;
    }
    [data-testid="stSidebar"] h1, [data-testid="stSidebar"] h2, [data-testid="stSidebar"] h3, [data-testid="stSidebar"] h4 {
        color: #2ecc71;
    }
    [data-testid="stSidebar"] .st-emotion-cache-16txtl3 {
        color: #F1F1F1; /* Sidebar Title Color */
    }

    /* --- Main Content Styling --- */
    h1, h2, h3, h4, h5, h6 {
        color: #F1F1F1;
    }

    /* Terminal-style title */
    h1 {
        font-size: 2.5em;
    }

    /* Subheader styling */
    h2 {
        border-bottom: 1px solid #2ecc71;
        padding-bottom: 8px;
    }
    h3 {
        color: #bdc3c7;
    }
    
    /* Input widgets styling */
    .stTextInput input, .stTextArea textarea {
        background-color: #2b2b2b;
        color: #F1F1F1;
        border: 1px solid #444;
        border-radius: 4px;
    }
    .stTextInput input:focus, .stTextArea textarea:focus {
        border-color: #2ecc71;
        box-shadow: none;
    }

    /* Button styling */
    .stButton>button {
        background-color: transparent;
        color: #2ecc71;
        border: 1px solid #2ecc71;
        border-radius: 4px;
        padding: 0.5em 1em;
        font-weight: bold;
        transition: all 0.2s ease-in-out;
    }
    .stButton>button:hover {
        background-color: #2ecc71;
        color: #1e1e1e;
        border-color: #2ecc71;
    }
    .stButton>button:focus {
        box-shadow: none !important;
        outline: none !important;
    }

    /* Radio button styling */
    .stRadio div[role="radiogroup"] > label {
        background-color: #2b2b2b;
        border: 1px solid #444;
        padding: 0.5em 1em;
        margin-bottom: 5px;
        border-radius: 4px;
        transition: all 0.2s;
    }
    .stRadio div[role="radiogroup"] > label:hover {
        border-color: #2ecc71;
    }
    
    /* Live Log (st.code) styling */
    [data-testid="stCodeBlock"] {
        background-color: #000000;
        border: 1px solid #444;
        border-radius: 5px;
        padding: 1em;
        font-size: 0.9em;
    }
    [data-testid="stCodeBlock"] code {
        color: #2ecc71;
        font-family: 'Consolas', 'Menlo', 'Courier New', monospace;
    }

    /* DataFrame styling */
    .stDataFrame {
        background-color: #2b2b2b;
        border: 1px solid #444;
    }
    .stDataFrame thead th {
        background-color: #2b2b2b;
        color: #2ecc71;
        border-bottom: 1px solid #2ecc71;
    }
    .stDataFrame tbody tr:nth-child(even) {
        background-color: #2b2b2b;
    }
    .stDataFrame tbody tr:nth-child(odd) {
        background-color: #313131;
    }
    .stDataFrame tbody td {
        color: #F1F1F1;
    }

    /* Success, Warning, Error boxes */
    [data-testid="stSuccess"], [data-testid="stWarning"], [data-testid="stError"] {
        border-radius: 5px;
        padding: 1em;
        color: #F1F1F1;
    }
    [data-testid="stSuccess"] {
        background-color: #1e3a2f;
        border: 1px solid #2ecc71;
    }
    [data-testid="stWarning"] {
        background-color: #3b3520;
        border: 1px solid #f1c40f;
    }
    [data-testid="stError"] {
        background-color: #3a2423;
        border: 1px solid #e74c3c;
    }
    
    /* File Uploader */
    [data-testid="stFileUploader"] {
        background-color: #2b2b2b;
        border: 2px dashed #444;
        border-radius: 5px;
    }
    [data-testid="stFileUploader"] span {
        color: #bdc3c7;
    }
    [data-testid="stFileUploader"]:hover {
        border-color: #2ecc71;
    }

    /* Markdown link styling */
    a {
        color: #3498db;
    }
    a:hover {
        color: #5dade2;
    }
    
    /* Remove the glowing border from the main content area */
    .main > div {
        border: none;
        box-shadow: none;
    }

    /* Separator styling */
    hr {
        background: #444;
        height: 1px;
        border: none;
    }

</style>
"""
st.markdown(MODERN_TERMINAL_THEME, unsafe_allow_html=True)


# --- Thread-Safe Logging Setup ---

def setup_queue_logging():
    """
    Configures the root logger to send logs to a thread-safe queue.
    Returns the queue so the main thread can read from it.
    """
    log_queue = queue.Queue()
    queue_handler = QueueHandler(log_queue)

    logger = logging.getLogger()
    logger.setLevel(logging.INFO)

    if logger.hasHandlers():
        logger.handlers.clear()

    logger.addHandler(queue_handler)
    return log_queue

# --- UI Helper Functions ---

def display_file_paths(basename: str, show_csv=True, show_report=True):
    """
    Displays a success message with the absolute paths to generated files.
    """
    st.success("**Action Completed Successfully!**")

    paths_to_show = []

    csv_file = f"{basename}.csv"
    md_file = f"{basename}.md"
    pdf_file = f"{basename}.pdf"

    if show_csv and os.path.exists(csv_file):
        abs_path = os.path.abspath(csv_file)
        paths_to_show.append(f"*   **Crawl Data (CSV):** `{abs_path}`")

    if show_report:
        if os.path.exists(md_file):
            abs_path = os.path.abspath(md_file)
            paths_to_show.append(f"*   **Markdown Report:** `{abs_path}`")
        if os.path.exists(pdf_file):
            abs_path = os.path.abspath(pdf_file)
            paths_to_show.append(f"*   **PDF Report:** `{abs_path}`")

    if paths_to_show:
        st.markdown("Your generated file(s) can be found at:")
        st.markdown("\n".join(paths_to_show))
    else:
        st.warning("Action completed, but no output files were found.")

def run_task_with_live_logs(task_function, *args, tail_lines=10):
    """
    Runs a function in a background thread and displays a tailed live log from a queue.
    """
    log_queue = setup_queue_logging()

    st.subheader(f"Live Log (showing last {tail_lines} entries)")
    log_placeholder = st.empty()
    log_records = []

    formatter = logging.Formatter(
        "%(asctime)s [%(levelname)s] :: %(message)s",
        "%H:%M:%S"
    )

    task_thread = threading.Thread(target=task_function, args=args, daemon=True)
    task_thread.start()

    while task_thread.is_alive():
        try:
            record = log_queue.get(block=False)
            log_records.append(formatter.format(record))
            log_placeholder.code("\n".join(log_records[-tail_lines:]), language="log")
        except queue.Empty:
            time.sleep(0.1)

    while not log_queue.empty():
        record = log_queue.get(block=False)
        log_records.append(formatter.format(record))

    log_placeholder.code("\n".join(log_records[-tail_lines:]), language="log")

# --- Streamlit App Layout ---

st.markdown("<h1><span style='color: #2ecc71;'>$</span> spectre_ui</h1>", unsafe_allow_html=True)
st.markdown("An Integrated Web Crawler and AI Reconnaissance Assistant.")
st.markdown("---")


st.sidebar.title("Configuration")
mode = st.sidebar.radio("Select Mode", ("Full Scan", "Crawl Only", "Analyze Only"))
st.sidebar.header("Shared Settings")

output_directory = st.sidebar.text_input(
    "Output Directory",
    ".",
    help="The folder where output files will be saved. Defaults to the current directory ('.')."
)

api_key = st.sidebar.text_input(
    "Gemini API Key", type="password",
    help="Required for 'Full Scan' and 'Analyze Only'."
)

# == FULL SCAN MODE ==
if mode == "Full Scan":
    st.header("🚀 Full Scan")
    with st.form(key='full_scan_form'):
        start_url = st.text_input("Start URL", "https://example.com")
        output_basename = st.text_input(
            "Output File Basename", "scan_report",
            help="E.g., 'scan_report' will create 'scan_report.csv', etc., in the specified output directory."
        )
        st.subheader("Crawler Settings")
        threads = st.slider("Number of Threads", 1, 50, 10)
        timeout = st.slider("Request Timeout (s)", 1, 30, 5)
        submit_button = st.form_submit_button(label='Start Full Scan')

    if submit_button:
        if not start_url: st.error("Please provide a Start URL.")
        elif not api_key: st.warning("Google API Key is missing. Please enter it in the sidebar.")
        else:
            os.makedirs(output_directory, exist_ok=True)
            full_output_basename = os.path.join(output_directory, output_basename)
            csv_filename = f"{full_output_basename}.csv"

            st.markdown("---")
            crawler = WebCrawler(start_url=start_url, num_threads=threads, timeout=timeout, output_filename=csv_filename)
            run_task_with_live_logs(crawler.run)
            st.success("Crawling complete.")

            st.markdown("---")
            if not os.path.exists(csv_filename) or os.path.getsize(csv_filename) == 0:
                 st.error(f"Crawler did not produce a valid output file. Aborting analysis.")
            else:
                with st.spinner("Generating AI security report..."):
                    try:
                        generator = SecurityReportGenerator(csv_path=csv_filename, output_basename=full_output_basename, api_key=api_key)
                        generator.generate_report()

                        st.header("📊 Analysis Report Preview")
                        md_file = f"{full_output_basename}.md"
                        if os.path.exists(md_file):
                            with open(md_file, 'r', encoding='utf-8') as f:
                                st.markdown(f.read(), unsafe_allow_html=True)

                        st.markdown("---")
                        display_file_paths(full_output_basename, show_csv=True, show_report=True)

                    except Exception as e:
                        st.error(f"A critical error occurred during analysis: {e}")

# == CRAWL ONLY MODE ==
elif mode == "Crawl Only":
    st.header("🕸️ Crawl Only")
    with st.form(key='crawl_form'):
        start_url = st.text_input("Start URL", "https://example.com")
        output_basename = st.text_input(
            "Output File Basename", "crawl_results",
            help="E.g., 'crawl_results' creates 'crawl_results.csv' in the specified output directory."
        )
        threads = st.slider("Number of Threads", 1, 50, 10)
        timeout = st.slider("Request Timeout (s)", 1, 30, 5)
        submit_button = st.form_submit_button(label='Start Crawl')

    if submit_button:
        if not start_url: st.error("Please provide a Start URL.")
        else:
            os.makedirs(output_directory, exist_ok=True)
            full_output_basename = os.path.join(output_directory, output_basename)
            output_csv = f"{full_output_basename}.csv"

            st.markdown("---")
            crawler = WebCrawler(start_url=start_url, num_threads=threads, timeout=timeout, output_filename=output_csv)
            run_task_with_live_logs(crawler.run)

            st.markdown("---")
            if os.path.exists(output_csv):
                display_file_paths(full_output_basename, show_csv=True, show_report=False)

                st.subheader("Crawl Results Preview")
                try:
                    st.dataframe(pd.read_csv(output_csv))
                except Exception as e:
                    st.warning(f"Could not display preview of CSV: {e}")
            else:
                st.error("Crawling finished, but the output CSV file was not found.")

# == ANALYZE ONLY MODE ==
elif mode == "Analyze Only":
    st.header("🔬 Analyze Only")
    uploaded_file = st.file_uploader("Upload your crawl_results.csv", type=['csv'])
    output_basename = st.text_input(
        "Output Report Basename", "security_analysis_report",
        help="Base name for the output .md and .pdf files in the specified directory."
    )

    if st.button("Generate Report"):
        if uploaded_file is None: st.warning("Please upload a CSV file.")
        elif not api_key: st.warning("Google API Key is missing.")
        else:
            os.makedirs(output_directory, exist_ok=True)
            full_output_basename = os.path.join(output_directory, output_basename)

            # Save uploaded file temporarily to a known path
            temp_csv_path = os.path.join(".", uploaded_file.name)
            with open(temp_csv_path, "wb") as f: f.write(uploaded_file.getbuffer())

            st.markdown("---")
            with st.spinner("Generating AI security report..."):
                try:
                    generator = SecurityReportGenerator(csv_path=temp_csv_path, output_basename=full_output_basename, api_key=api_key)
                    generator.generate_report()

                    st.header("📊 Analysis Report Preview")
                    md_file = f"{full_output_basename}.md"
                    if os.path.exists(md_file):
                        with open(md_file, 'r', encoding='utf-8') as f:
                            st.markdown(f.read(), unsafe_allow_html=True)

                    st.markdown("---")
                    display_file_paths(full_output_basename, show_csv=False, show_report=True)
                except Exception as e:
                    st.error(f"Analysis failed: {e}")
                finally:
                    if os.path.exists(temp_csv_path): os.remove(temp_csv_path)