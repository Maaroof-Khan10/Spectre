#!/usr/bin/env python3
#
#  Spectre: An Integrated Web Crawler and AI Security Analyzer
#
#  This tool combines a multi-threaded web crawler with a generative AI-powered
#  security report generator.
#
#  Sub-commands:
#    - crawl:      Discovers and enumerates web pages, saving results to a CSV.
#    - analyze:    Analyzes a pre-existing CSV file to generate a security report.
#    - full-scan:  Performs a complete crawl and analysis in one go.
#
#  Usage Examples:
#    # 1. Perform a full scan on a target, generating a report named 'my_target'
#    # (will create my_target.csv, my_target.md, and my_target.pdf)
#    python spectre.py full-scan https://example.com -o my_target
#
#    # 2. Just crawl a website and save the output to a specific CSV file
#    python spectre.py crawl https://example.com --output-csv results/crawl.csv
#
#    # 3. Analyze an existing CSV file
#    python spectre.py analyze results/crawl.csv --output-report final_report
#

import argparse
import csv
import logging
import os
import pathlib
import sys
import threading
import time
from queue import Queue
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse

import google.generativeai as genai
import markdown
import requests
from bs4 import BeautifulSoup, Tag
from weasyprint import HTML

# --- Global Configuration ---
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] (%(threadName)s) %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

# --- Type Aliases for Clarity ---
Url = str
FormSignature = Tuple[Url, str, Tuple[str, ...]]


# ==============================================================================
# SCRIPT 1: WEB CRAWLER
# ==============================================================================

class WebCrawler:
    """
    A thread-safe web crawler that discovers links and forms within a specified domain.
    """
    CSV_HEADERS = ["request_type", "status_code", "url", "title", "has_parameters"]

    def __init__(
        self,
        start_url: Url,
        num_threads: int = 10,
        timeout: int = 5,
        output_filename: str = "crawl_results.csv",
        max_visits_per_path: int = 20,
    ):
        self.start_url: Url = start_url
        parsed_start_url = urlparse(self.start_url)
        if not parsed_start_url.scheme or not parsed_start_url.netloc:
            raise ValueError("Invalid start URL provided. Must include scheme and domain.")
        self.base_domain: str = parsed_start_url.netloc

        self.num_threads: int = num_threads
        self.timeout: int = timeout
        self.output_filename: str = output_filename
        self.max_visits_per_path: int = max_visits_per_path
        self.session: requests.Session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Spectre/1.0 (Security Scanner)"
        })
        self.url_queue: Queue[Url] = Queue()
        self.visited_urls: Set[Url] = set()
        self.path_visit_counts: Dict[str, int] = {}
        self.visited_forms: Set[FormSignature] = set()
        self.lock: threading.Lock = threading.Lock()
        self.stop_event: threading.Event = threading.Event()
        self.active_threads = threading.active_count() - 1 
        self.csv_writer = None
        self.output_file = None

    def run(self) -> None:
        start_time = time.time()
        logging.info(f"Starting crawl at {self.start_url} with {self.num_threads} threads.")
        logging.info(f"Path recursion limit set to {self.max_visits_per_path} visits per unique path.")
        logging.info(f"Data will be saved to '{self.output_filename}'.")
        logging.info("Press Ctrl+C for a graceful shutdown.")

        try:
            self._setup_csv()
            self._start_workers()
            self._queue_url(self.start_url)

            while not self.url_queue.empty():
                if self.stop_event.is_set():
                    break
                time.sleep(1)

            self.url_queue.join()

        except KeyboardInterrupt:
            logging.warning("Ctrl+C detected! Signaling threads to stop...")
            self.stop_event.set()
        except Exception as e:
            logging.critical(f"A critical error occurred during crawl: {e}", exc_info=True)
        finally:
            if self.stop_event.is_set():
                logging.info("Waiting for active threads to finish their current task...")
                time.sleep(self.timeout + 1)
            self._shutdown()
            end_time = time.time()
            logging.info(f"Crawl finished in {end_time - start_time:.2f} seconds.")

    def _setup_csv(self) -> None:
        try:
            output_dir = os.path.dirname(self.output_filename)
            if output_dir:
                os.makedirs(output_dir, exist_ok=True)
            self.output_file = open(self.output_filename, 'w', newline='', encoding='utf-8')
            self.csv_writer = csv.DictWriter(self.output_file, fieldnames=self.CSV_HEADERS)
            self.csv_writer.writeheader()
        except IOError as e:
            logging.critical(f"Could not create or write to CSV file '{self.output_filename}': {e}")
            sys.exit(1)

    def _start_workers(self) -> None:
        for i in range(self.num_threads):
            thread = threading.Thread(target=self._worker, name=f"Worker-{i+1}", daemon=True)
            thread.start()

    def _worker(self) -> None:
        while not self.stop_event.is_set():
            try:
                url = self.url_queue.get(timeout=1)
                self._process_url(url)
                self.url_queue.task_done()
            except Exception:
                continue

    def _process_url(self, url: Url) -> None:
        try:
            response = self.session.get(url, timeout=self.timeout)
            response.raise_for_status()
        except requests.RequestException as e:
            logging.warning(f"Request failed for {url}: {e}")
            return
        content_type = response.headers.get("Content-Type", "").lower()
        if "html" not in content_type:
            logging.debug(f"Skipping non-HTML content at {url}")
            return
        soup = BeautifulSoup(response.content, "lxml")
        self._process_response(response, soup)

    def _process_response(self, response: requests.Response, soup: BeautifulSoup) -> None:
        url = str(response.url)
        title = soup.title.string.strip() if soup.title else "No Title"
        self._write_to_csv({
            "request_type": response.request.method,
            "status_code": response.status_code,
            "url": url,
            "title": title,
            "has_parameters": bool(urlparse(url).query),
        })
        self._discover_and_queue_links(url, soup)
        for form_tag in soup.find_all("form"):
            self._submit_form(form_tag, url)

    @staticmethod
    def _normalize_url(url: Url) -> Url:
        parts = urlparse(url)
        query = sorted(parse_qsl(parts.query))
        normalized_parts = parts._replace(
            scheme=parts.scheme.lower(),
            netloc=parts.netloc.lower(),
            query=urlencode(query),
            fragment="",
        )
        return urlunparse(normalized_parts)

    def _is_in_scope(self, url: Url) -> bool:
        try:
            return urlparse(url).netloc.endswith(self.base_domain)
        except Exception:
            return False

    def _queue_url(self, url: Url) -> None:
        """
        Queues a URL for crawling after checking against visited URLs and path recursion limits.
        """
        normalized_url = self._normalize_url(url)

        url_path = urlunparse(urlparse(normalized_url)._replace(query="", fragment=""))

        with self.lock:
            if normalized_url in self.visited_urls:
                return

            path_count = self.path_visit_counts.get(url_path, 0)
            if path_count >= self.max_visits_per_path:
                if path_count == self.max_visits_per_path: 
                    logging.warning(f"Path limit of {self.max_visits_per_path} reached for path: {url_path}. "
                                    f"Skipping this and future similar URLs.")
                    self.path_visit_counts[url_path] = path_count + 1 
                return

            self.visited_urls.add(normalized_url)
            self.path_visit_counts[url_path] = path_count + 1
            self.url_queue.put(url)


    def _discover_and_queue_links(self, base_url: Url, soup: BeautifulSoup) -> None:
        links_found = 0
        for link_tag in soup.find_all("a", href=True):
            href = link_tag["href"]
            if not href or href.startswith(("mailto:", "tel:", "javascript:")):
                continue
            full_url = urljoin(base_url, href)
            if self._is_in_scope(full_url):
                self._queue_url(full_url)
                links_found += 1
        logging.info(f"Crawled (GET): {base_url} | Found {links_found} links | Queue: {self.url_queue.qsize()}")

    def _submit_form(self, form_tag: Tag, current_url: Url) -> None:
        try:

            action = form_tag.get("action")
            submission_url = urljoin(current_url, action)
            method = form_tag.get("method", "get").upper()

            parsed_current = urlparse(current_url)
            clean_base_for_signature = urlunparse(
                (parsed_current.scheme, parsed_current.netloc, parsed_current.path, '', '', '')
            )
            signature_action_url = urljoin(clean_base_for_signature, action)

            inputs = form_tag.find_all(["input", "select", "textarea"])
            input_names = sorted([inp.get("name") for inp in inputs if inp.get("name")])
            
            form_signature = (self._normalize_url(signature_action_url), method, tuple(input_names))

            with self.lock:
                if form_signature in self.visited_forms:
                    return
                self.visited_forms.add(form_signature)

            payload = self._generate_form_data(inputs)
            logging.info(f"Found new {method} form. Submitting to: {submission_url} with data: {payload}")

            if method == "POST":
                response = self.session.post(submission_url, data=payload, timeout=self.timeout)
            else:
                response = self.session.get(submission_url, params=payload, timeout=self.timeout)

            response.raise_for_status()
            if "html" in response.headers.get("Content-Type", "").lower():
                form_soup = BeautifulSoup(response.content, "lxml")
                self._process_response(response, form_soup)
        except requests.RequestException as e:
            logging.error(f"Error submitting form to {submission_url}: {e}")
        except Exception as e:
            logging.error(f"An unexpected error occurred during form submission: {e}")

    @staticmethod
    def _generate_form_data(inputs: List[Tag]) -> Dict[str, str]:
        payload = {}
        for inp in inputs:
            name = inp.get("name")
            if not name:
                continue
            inp_type = inp.get("type", "text").lower()
            if inp_type in ["submit", "button", "reset", "image"]:
                continue
            elif inp_type == "password":
                payload[name] = "password123"
            elif inp_type == "email":
                payload[name] = "test@example.com"
            else:
                payload[name] = "testvalue"
        return payload

    def _write_to_csv(self, data_row: Dict) -> None:
        with self.lock:
            try:
                if self.csv_writer:
                    self.csv_writer.writerow(data_row)
            except (IOError, AttributeError) as e:
                logging.error(f"Error writing to CSV: {e}")

    def _shutdown(self) -> None:
        if self.output_file and not self.output_file.closed:
            self.output_file.close()
            logging.info(f"Successfully saved data to '{self.output_filename}'.")


# ==============================================================================
# SCRIPT 2: AI SECURITY REPORT GENERATOR
# ==============================================================================

class SecurityReportGenerator:
    """
    Analyzes web crawler data to generate an AI-driven security report.
    """
    ANALYSIS_PROMPT = """
        ### ROLE & MISSION ###
        You are an elite offensive security analyst. Your mission is to analyze the provided web crawler data (in CSV format) and identify the most promising potential attack vectors. You must think like a creative and methodical attacker looking for an initial foothold.

        ### INPUT DATA SCHEMA ###
        The provided CSV data contains the following columns:
        - `url`: The full URL of the request.
        - `title`: The HTML title of the page, if available.
        - `status_code`: The HTTP status code returned (e.g., 200, 403, 500).
        - `request_type`: The HTTP method used (e.g., GET, POST).
        - `has_parameters`: A boolean (`True`/`False`) indicating if the URL has query parameters or if the request was a POST with a body.

        ### ATTACKER'S HEURISTICS (Apply these rules) ###
        1.  **Prioritize Parameters:** Any URL where `has_parameters` is `True` is a high-priority target. Immediately consider injection attacks (SQLi, XSS, Command Injection, LFI/RFI). `POST` requests with parameters are especially interesting.
        2.  **Hunt for Sensitive Keywords:** Scrutinize URLs and titles for keywords like: `login`, `admin`, `dashboard`, `api`, `config`, `upload`, `backup`, `debug`, `test`, `user`, `account`, `password`, `redirect`. These often point to critical functionality.
        3.  **Analyze Status Codes:**
            - `401 Unauthorized` / `403 Forbidden`: Indicates protected areas. Could be vulnerable to access control bypasses (IDOR) or brute-forcing.
            - `5xx Server Error`: A major red flag. Suggests application instability and potential for information leakage (e.g., stack traces, database errors).
            - `301/302 Redirect`: Look for open redirects, especially if a parameter controls the redirection target.
        4.  **Evaluate Request Types:** `POST`, `PUT`, and `DELETE` requests are more likely to change data on the server than `GET` requests. They are prime targets for causing state changes or triggering vulnerabilities.
        5.  **Title Analysis:** Titles can reveal functionality or sensitive areas. Look for titles that suggest admin panels, user management, or configuration interfaces.
        6.  **Check for all OWASP Top 10 vulnerabilities:** If the url suggests that it could be vulnerable to any of the OWASP Top 10 vulnerabilities, give a PoC for each one.

        ### OUTPUT FORMAT ###
        - Add a title to the report.
        - Do not write an introduction, conclusion, or any conversational text.
        - Go straight to the analysis.
        - Make sure the format does not have any errors
        - Present your findings as a list of actionable hypotheses.
        - Add a separate section called exploitation and checking proof of concept (PoC). And give a steps on how to exploit the vulnerabilities found.
        - Use markdown and make the report look sleek and professional.
        - Use different markdown styles to highlight important findings.
        - Check for every vulnerability and provide a PoC for each one.
        - End with a guide section adding more reconnaissance steps to take, tools to use, and how to proceed with exploitation.

        **REQUIRED MARKDOWN STRUCTURE:**
        # Spectre scan/report for {target_domain}

        ## Potential Attack Vectors Analysis

        ### High-Priority Targets
        *List any findings that match multiple heuristics (e.g., a POST request to an admin login with parameters).*

        ### Interesting Endpoints & Hypotheses
        *For each potential vector, use the following format:*

        - **URL:** `The URL`
        - **Hypothesis:** `A concise attack hypothesis, e.g., "Potential SQL Injection"`
        - **Rationale:** `Briefly explain WHY you think this, based on the heuristics. E.g., "POST request with parameters to a login page."`

        ### Exploitation and PoC
        *For each hypothesis, provide a step-by-step guide on how to exploit it, including any tools or techniques that could be used. Be specific and actionable.*

        ### Guide for Further Reconnaissance
        *Provide a list of additional reconnaissance steps, tools, or techniques that could be used to further investigate the identified vulnerabilities. This could include specific tools, commands, or methodologies.*

        ---

        ### CRAWLER DATA ANALYSIS ###
        Here is the CSV data to analyze:

        {csv_data}
        """

    def __init__(self, csv_path: str, output_basename: str, api_key: Optional[str] = None):
        self.csv_path = pathlib.Path(csv_path)
        self.output_md = pathlib.Path(f"{output_basename}.md")
        self.output_pdf = pathlib.Path(f"{output_basename}.pdf")
        self.api_key = self._get_api_key(api_key)
        self.model = None

    @staticmethod
    def _get_api_key(cli_key: Optional[str]) -> str:
        """Retrieves the API key from CLI arg or environment variable."""
        key = cli_key or os.getenv('GOOGLE_API_KEY')
        if not key:
            logging.error("API key not found. Please provide it via --api-key or set the GOOGLE_API_KEY environment variable.")
            raise ValueError("API key not found.")
        return key

    def _read_csv_content(self) -> Optional[str]:
        try:
            with self.csv_path.open('r', encoding='utf-8') as file:
                content = file.read()
                if not content.strip() or len(content.splitlines()) <= 1:
                    logging.warning(f"CSV file is empty or only contains headers: {self.csv_path}")
                    return None
                return content
        except FileNotFoundError:
            logging.error(f"Input file not found: {self.csv_path}")
            return None
        except IOError as e:
            logging.error(f"Could not read file {self.csv_path}: {e}")
            return None

    def _get_target_domain_from_csv(self, csv_data: str) -> str:
        """Extracts the base domain from the first URL in the CSV data."""
        try:
            reader = csv.reader(csv_data.splitlines())
            header = next(reader)
            first_row = next(reader)
            url_index = header.index("url")
            first_url = first_row[url_index]
            return urlparse(first_url).netloc
        except (StopIteration, ValueError, IndexError):
            return "Unknown Target"

    def analyze_results(self, csv_data: str) -> Optional[str]:
        try:
            logging.info("Configuring Generative AI model...")
            genai.configure(api_key=self.api_key)
            self.model = genai.GenerativeModel('gemini-2.5-pro')
            target_domain = self._get_target_domain_from_csv(csv_data)

            prompt = self.ANALYSIS_PROMPT.format(
                csv_data=csv_data,
                target_domain=target_domain
            )

            logging.info(f"Sending data for '{target_domain}' to the AI for analysis. This may take a moment...")
            response = self.model.generate_content(prompt)

            if not response.parts:
                if response.prompt_feedback.block_reason:
                    logging.error(f"Analysis was blocked. Reason: {response.prompt_feedback.block_reason.name}")
                else:
                    logging.error("Analysis failed: Received an empty response from the API.")
                return None
            return response.text
        except Exception as e:
            logging.error(f"An unexpected error occurred during API call: {e}")
            return None

    def _save_markdown(self, content: str) -> None:
        try:
            with self.output_md.open('w', encoding='utf-8') as file:
                file.write(content)
            logging.info(f"Analysis report saved to {self.output_md}")
        except IOError as e:
            logging.error(f"Error saving Markdown report to {self.output_md}: {e}")

    def _save_pdf(self, content: str) -> None:
        try:
            html_content = markdown.markdown(content)
            HTML(string=html_content).write_pdf(self.output_pdf)
            logging.info(f"PDF report saved to {self.output_pdf}")
        except Exception as e:
            logging.error(f"Failed to generate PDF report. WeasyPrint error: {e}")
            logging.warning("Please ensure system dependencies for WeasyPrint (like Pango, cairo) are installed.")

    def generate_report(self) -> None:
        logging.info(f"Starting analysis for {self.csv_path}...")
        csv_content = self._read_csv_content()

        if not csv_content:
            logging.error("Aborting analysis due to missing or empty CSV data.")
            return

        analysis_report = self.analyze_results(csv_content)

        if not analysis_report:
            logging.error("Aborting report generation due to failed analysis.")
            return

        self._save_markdown(analysis_report)
        self._save_pdf(analysis_report)
        logging.info("Report generation complete.")


# ==============================================================================
# MAIN CLI ORCHESTRATOR
# ==============================================================================

def main():
    """Parses command-line arguments and runs the appropriate tool command."""
    parser = argparse.ArgumentParser(
        description="Spectre: An Integrated Web Crawler and AI Security Analyzer.",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Usage Examples:
  # Perform a full scan (crawl and analyze) on a target
  %(prog)s full-scan https://example.com -o my_report --api-key YOUR_API_KEY

  # Just crawl a website and save results
  %(prog)s crawl https://example.com -t 20 --output-csv results.csv

  # Analyze an existing CSV file
  %(prog)s analyze results.csv --output-report analysis_report
"""
    )
    subparsers = parser.add_subparsers(dest="command", required=True, help="Available commands")

    # --- 'crawl' command ---
    crawl_parser = subparsers.add_parser(
        'crawl',
        help='Crawl a website and save discovered URLs to a CSV file.',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    crawl_parser.add_argument('start_url', help="The URL to start crawling from.")
    crawl_parser.add_argument('-t', '--threads', type=int, default=10, help="Number of worker threads.")
    crawl_parser.add_argument('--timeout', type=int, default=5, help="Request timeout in seconds.")
    crawl_parser.add_argument('--output-csv', default="crawl_results.csv", help="Path for the output CSV file.")

    # --- 'analyze' command ---
    analyze_parser = subparsers.add_parser(
        'analyze',
        help='Analyze an existing crawler CSV file to generate a security report.',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    analyze_parser.add_argument('input_csv', help="Path to the input CSV file from the crawler.")
    analyze_parser.add_argument('--output-report', default="security_analysis_report", help="Base name for the output .md and .pdf files.")
    analyze_parser.add_argument('--api-key', help="Google API Key. Overrides GOOGLE_API_KEY env var.")

    # --- 'full-scan' command ---
    full_scan_parser = subparsers.add_parser(
        'full-scan',
        help='Perform a full scan: crawl a website and then immediately analyze the results.',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    full_scan_parser.add_argument('start_url', help="The URL to start the scan from.")
    full_scan_parser.add_argument('-t', '--threads', type=int, default=10, help="Number of worker threads for crawling.")
    full_scan_parser.add_argument('--timeout', type=int, default=5, help="Request timeout in seconds for crawling.")
    full_scan_parser.add_argument('-o', '--output-basename', default="scan_report", help="Base name for all output files (e.g., 'scan_report' -> scan_report.csv, .md, .pdf).")
    full_scan_parser.add_argument('--api-key', help="Google API Key. Overrides GOOGLE_API_KEY env var.")

    args = parser.parse_args()

    try:
        if args.command == 'crawl':
            crawler = WebCrawler(
                start_url=args.start_url,
                num_threads=args.threads,
                timeout=args.timeout,
                output_filename=args.output_csv,
            )
            crawler.run()

        elif args.command == 'analyze':
            generator = SecurityReportGenerator(
                csv_path=args.input_csv,
                output_basename=args.output_report,
                api_key=args.api_key
            )
            generator.generate_report()

        elif args.command == 'full-scan':
            csv_filename = f"{args.output_basename}.csv"

            # --- Step 1: Crawl ---
            logging.info("--- Starting Step 1: Web Crawling ---")
            crawler = WebCrawler(
                start_url=args.start_url,
                num_threads=args.threads,
                timeout=args.timeout,
                output_filename=csv_filename,
            )
            crawler.run()

            # --- Step 2: Analyze ---
            logging.info("--- Starting Step 2: AI Security Analysis ---")
            if not os.path.exists(csv_filename):
                logging.error(f"Crawler did not produce an output file at '{csv_filename}'. Aborting analysis.")
                sys.exit(1)

            generator = SecurityReportGenerator(
                csv_path=csv_filename,
                output_basename=args.output_basename,
                api_key=args.api_key
            )
            generator.generate_report()
            logging.info("Full scan completed successfully.")

    except ValueError as e:
        logging.critical(f"Configuration error: {e}")
        sys.exit(1)
    except Exception as e:
        logging.critical(f"A fatal error occurred: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()