# Spectre: AI-Powered Reconnaissance Partner

[![Python Version](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Gemini Version](https://img.shields.io/badge/gemini-2.5-blue.svg)](https://aistudio.google.com)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

In cybersecurity, the initial reconnaissance phase is critical, and often tedious. Spectre automates and supercharges this process. It fuses a high-speed, multi-threaded web crawler with a generative AI security analyst to map your target's attack surface and pinpoint potential vulnerabilities before attackers do.

Operate via a sleek **Streamlit GUI** for interactive analysis or a powerful **CLI** for automation and integration.

## See it in Action

**Spectre UI**

![Spectre UI](https://github.com/Maaroof-Khan10/Spectre/blob/552cc963a32ebb7f641399dd94fd9e4f343fd7e4/Screenshot%202025-07-20%20190022.png)

**Log and Report Preview**

![Spectre Log and Report Preview](https://github.com/Maaroof-Khan10/Spectre/blob/552cc963a32ebb7f641399dd94fd9e4f343fd7e4/Screenshot%202025-07-20%20190152.png)

**List of exploitation tests that can be done**

![Spectre Exploitation](https://github.com/Maaroof-Khan10/Spectre/blob/552cc963a32ebb7f641399dd94fd9e4f343fd7e4/Screenshot%202025-07-20%20190222.png)

**Sample PDF Report**

Dive into a sample [PDF Report](https://github.com/Maaroof-Khan10/Spectre/blob/552cc963a32ebb7f641399dd94fd9e4f343fd7e4/sample_report.pdf) to see the detailed, actionable output Spectre generates.

## Why Spectre?

Spectre is more than just a crawler; it's an intelligent reconnaissance assistant.

*   ### 🚀 Find More, Faster
    A resilient, multi-threaded crawler rapidly spiders websites, discovering links and submitting forms to uncover hidden endpoints. It's built to map complex applications quickly.

*   ### 🧠 Think Like an Attacker
    Spectre leverages Google's Gemini Pro with a custom-engineered prompt that embeds offensive security heuristics. It doesn't just list URLs; it analyzes them for signs of OWASP Top 10 vulnerabilities, sensitive exposures, and potential misconfigurations.

*   ### 📊 From Data to Actionable Insights
    Don't drown in data. Spectre automatically generates professional security reports in both Markdown and PDF, translating raw crawl data into clear, actionable hypotheses and providing guidance for PoCs and further reconnaissance.

*   ### 💻 Dual-Interface for Any Workflow
    Whether you prefer a visual, interactive experience or the speed of the command line, Spectre has you covered. The Streamlit GUI is perfect for demos and deep dives, while the CLI is built for scripting and automation.

## How It Works: The Hunt

Spectre follows a two-stage workflow designed to mimic the initial phase of a professional penetration test.

1.  **The Hunt Begins (Crawl):** The multi-threaded crawler is unleashed on a target URL. It scours the site for links and forms, saving all findings (URLs, status codes, methods, etc.) to a `.csv` file.
2.  **The AI Analyst Takes Over (Analyze):** The `.csv` data is fed to the Gemini AI model. The specialized prompt guides the AI to think like a security researcher, correlating data points to identify high-priority targets and form attack hypotheses.
3.  **The Verdict (Report):** The AI's findings are structured into a clean, professional report in Markdown and PDF formats, ready for review and further testing.

## ⚙️ Tech Stack

-   **Backend & Core Logic**: Python 3
-   **Web Crawling**: `requests`, `beautifulsoup4`
-   **AI Integration**: `google-generativeai` (Google Gemini)
-   **GUI**: `streamlit`
-   **Data Handling**: `pandas`
-   **Report Generation**: `markdown`, `weasyprint` (PDF)
-   **Concurrency**: `threading`, `queue`

## Getting Started in 3 Steps

Get Spectre running on your local machine in minutes.

### 1. Prerequisites
- Python 3.11+
- System dependencies for `WeasyPrint` (for PDF generation). See the [WeasyPrint documentation](https://doc.weasyprint.org/en/stable/install.html).
  - *On Debian/Ubuntu: `sudo apt-get install libpango-1.0-0 libpangoft2-1.0-0`*

### 2. Installation
**Clone** the repository, create a **virtual environment**, and **install dependencies**.

```bash
# Clone the repo
git clone https://github.com/Maaroof-Khan10/Spectre.git
cd Spectre

# Set up and activate a virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install all required packages
pip install -r requirements.txt
```

### 3. Configure API Key
Spectre needs a Google Gemini API Key to function.

- Get your key from [Google AI Studio](https://aistudio.google.com/app/apikey).
- Create a `.env` file in the project root and add your key:

```
GOOGLE_API_KEY="YOUR_API_KEY_HERE"
```
The application will load this key automatically.

## 🚀 Launching Spectre

### The Visual Experience (Streamlit UI)
For an interactive session, launch the Streamlit app.

```bash
streamlit run spectreUI.py
```
Open the provided local URL in your browser and start scanning!

### The Power User's Choice (CLI)
For automation and scripting, the CLI is your best friend.

**Full Scan (Crawl & Analyze):**
```bash
python spectre.py full-scan https://example.com -o target_report
```

**Crawl Only:**
```bash
python spectre.py crawl https://example.com -t 20 --output-csv results/crawl.csv
```

**Analyze Only:**
```bash
python spectre.py analyze results/crawl.csv --output-report analysis
```
Use `python spectre.py [command] -h` for all options.

## ⚠️ Troubleshooting & Notes

The web crawler is designed to be aggressive. On highly complex or JavaScript-heavy sites, it may occasionally slow down or get stuck.

**If the script seems stuck:** `Ctrl+C` might work, but the most reliable solution is to **manually kill the script process**. Don't worry about losing data! All discovered endpoints are saved to the `.csv` file in real-time, so you can simply run the `analyze` command on the partially completed file.

This project demonstrates a blend of key skills relevant to a modern cybersecurity role:
- **Offensive Security Mindset:** The core logic and AI prompts are built around attacker heuristics.
- **AI Integration & Prompt Engineering:** Skillfully guiding a powerful LLM to perform a specialized, technical task.
- **Software Architecture & Python Development:** Clean, modular, and robust code structure with classes for distinct responsibilities.
- **Full-Stack Tooling:** Experience with both backend (Python, CLI) and frontend (Streamlit) development.
- **Automation & Efficiency:** Creating a tool that significantly speeds up a critical but time-consuming security task.

## License
This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
