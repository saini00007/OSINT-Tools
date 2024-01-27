import re
import requests
import pdfkit
from bs4 import BeautifulSoup
import whois
import ssl
import socket
import os

def extract_emails(url):
    if not url.startswith('http://') and not url.startswith('https://'):
        url = 'https://' + url

    response = requests.get(url)

    if response.status_code == 200:
        email_pattern = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
        emails = re.findall(email_pattern, response.text)
        
        return emails
    else:
        print(f"Failed to retrieve the webpage. Status code: {response.status_code}")
        return []

def is_valid_url(url):
    url_pattern = re.compile(r"^((?!-)[A-Za-z0-9-]" + "{1,63}(?<!-)\\.)" +"+[A-Za-z]{2,6}")
    return bool(re.match(url_pattern, url))


def virustotal_scan(api_key, url, pdf_filename):
    extracted_emails = extract_emails(url)

    params = {'apikey': api_key, 'resource': url}
    scan_url = 'https://www.virustotal.com/vtapi/v2/url/report'
    response = requests.get(scan_url, params=params)
    scan_result = response.json()

    if scan_result['response_code'] != 1:
        print(f"Error: {scan_result['verbose_msg']}")
        return

    html_result = f"""
    <html>
    <head>
         <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Report for {url}</title>
    <style>
        body {{
            font-family: 'Times new romon', sans-serif;
            background-color: #f8f8f8;
            margin: 20px;
            padding: 20px;
            text-align: center;
        }}
        
        h1, h2 {{
            color: #333;
            text-align: center;
        }}

        p, li {{
            color: #555;
            text-align: left;
        }}

        ul, ol {{
            list-style-type: none;
            padding: 0;
            text-align: left
        }}

        strong {{
            color: #007bff;
        }}

        h2 {{
            border-bottom: 2px solid #007bff;
            padding-bottom: 5px;
            margin-top: 20px;
        }}

        ul {{
            margin-top: 15px;
            text-align: left;
        }}

        li {{
            margin-bottom: 5px;
        }}
    </style>
    </head>
   
    <body style="background-color:white;">
        <h1>Scan Report for {url}</h1>
        <p><strong>URL:</strong> {url}</p>
        <h2>Virustotal Report</h2>
   
        <p><strong>Scan Date:</strong> {scan_result['scan_date']}</p>
        <p><strong>Positives:</strong> {scan_result['positives']}</p>
        <p><strong>Total:</strong> {scan_result['total']}</p>
        <h2>Scan Results:</h2>
        <ol>
    """

    for scan_engine, result in scan_result['scans'].items():
        html_result += f"<li><strong>{scan_engine}:</strong> {result['result']}</li>"

    if extracted_emails:
        html_result += """
            </ol>
            <h2>Scraped Email Addresses:</h2>
            <ul>
        """
        for email in extracted_emails:
            html_result += f"<li>{email}</li>"
        html_result += "</ul>"

    domain_info = get_domain_information(url)
    if domain_info:
        html_result += """
            <h2>Domain Information:</h2>
            <ul>
        """
        for key, value in domain_info.items():
            html_result += f"<li><strong>{key}:</strong> {value}</li>"
        html_result += "</ul>"

    try:
        ssl_cert, tls_cert = get_certificates(url)
        html_result += """
            <h2>SSL Certificate Information:</h2>
            <ul>
        """
        html_result = print_certificate_info(ssl_cert, html_result)
        html_result += "</ul>"

    except ssl.SSLError as e:
        print(f"Error retrieving certificates: {e}")
    except socket.error as e:
        print(f"Error connecting to the server: {e} ")
        print(f"Certificate Informations not avilable..")

    html_content = get_html_content(url)
    if html_content:
        content_analysis = analyze_content(html_content)
        html_result += """
            <h2>Content Analysis:</h2>
            <ul>
        """
        for key, value in content_analysis.items():
            html_result += f"<li><strong>{key.capitalize()}:</strong> {value}<br></li>"
        html_result += "</ul>"

    http_headers = get_http_headers(url)
    if http_headers:
        web_technologies = identify_web_technologies(http_headers)
        html_result += """
            <h2>Technologies Uses:</h2>
            <ul>
        """
        for key, value in web_technologies.items():
            html_result += f"<li><strong>{key}:</strong> {value}</li>"
        html_result += "</ul>"

    html_result += """
        </body>
    </html>
    """

    html_file_path = 'report.html'
    with open(html_file_path, 'w') as html_file:
        html_file.write(html_result)

    
    pdf(html_file_path, pdf_filename)

def pdf(html_file_path, pdf_filename):
    pdfkit.from_file(html_file_path, pdf_filename + '.pdf')
    print(f"Your Scan report is saved as {pdf_filename}.pdf")

    try:
        os.remove(html_file_path)
       
    except OSError as e:
        print(f"Error deleting {html_file_path}: {e}")
def clean_filename(url):
    return re.sub(r'[^a-zA-Z0-9_.-]', '_', url)

def get_domain_information(url):
    try:
        domain_info = whois.whois(url)
        return domain_info

    except whois.parser.PywhoisError as e:
        print(f"Error getting domain information: {e}")
        return None

def get_certificates(hostname, port=443):
    context = ssl.create_default_context()

    with socket.create_connection((hostname, port)) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
            ssl_cert = ssock.getpeercert()

    with socket.create_connection((hostname, port)) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
            tls_cert = ssock.getpeercert()

    return ssl_cert, tls_cert

def print_certificate_info(cert, html_result):
    html_result += f"<li><strong>Subject:</strong> {cert.get('subject', 'N/A')}</li>"
    html_result += f"<li><strong>Issuer:</strong> {cert.get('issuer', 'N/A')}</li>"
    html_result += f"<li><strong>Expiry Date:</strong> {cert.get('notAfter', 'N/A')}</li>"
    html_result += f"<li><strong>Serial Number:</strong> {cert.get('serialNumber', 'N/A')}</li>"
    html_result += f"<li><strong>Signature Algorithm:</strong> {cert.get('signatureAlgorithm', 'N/A')}</li>"
    html_result += f"<li><strong>Public Key Algorithm:</strong> {cert.get('subjectPublicKeyAlgorithm', 'N/A')}</li>"
    html_result += f"<li><strong>Public Key Size:</strong> {cert.get('subjectPublicKeySize', 'N/A')} bits</li>"

    return html_result 

def get_html_content(url):
    if not url.startswith('http://') and not url.startswith('https://'):
        url = 'https://' + url

    try:
        response = requests.get(url)
        response.raise_for_status()
        return response.text
    except requests.RequestException as e:
        print(f"Error accessing the webpage: {e}")
        return None

def analyze_content(html_content):
    if not html_content:
        return None

    soup = BeautifulSoup(html_content, 'html.parser')

    title = soup.title.text.strip() if soup.title else 'N/A'
    meta_description = soup.find('meta', attrs={'name': 'description'})
    meta_description = meta_description['content'].strip() if meta_description else 'N/A'

    links = [link['href'] for link in soup.find_all('a', href=True)]

    paragraphs = [p.text.strip() for p in soup.find_all('p')]

    headings = [heading.text.strip() for heading in soup.find_all(['h1', 'h2', 'h3', 'h4', 'h5', 'h6'])]
    images = [img['src'] for img in soup.find_all('img', src=True)]

    return {
        'title': title,
        'meta_description': meta_description,
        'headings': headings,
        'links': links,
        'paragraphs': paragraphs,
        'images': images
    }

def get_http_headers(url):
    if not url.startswith('http://') and not url.startswith('https://'):
        url = 'https://' + url

    try:
        response = requests.head(url, allow_redirects=True)
        response.raise_for_status()
        return response.headers
    except requests.RequestException as e:
        print(f"Error accessing the webpage: {e}")
        return None

def identify_web_technologies(http_headers):
    if not http_headers:
        return None

    technologies = {
        'Server': http_headers.get('Server', 'Unknown'),
        'X-Powered-By': http_headers.get('X-Powered-By', 'Not specified'),
        'X-AspNet-Version': http_headers.get('X-AspNet-Version', 'Not specified'),
    }

    return technologies

if __name__ == "__main__":

 print(r"""  _   _      _ _
 | | | |    (_) |
 | | | |_ __  _| |_ ___
 | | | | '_ \| | __/ _ \
 | |_| | | | | | ||  __/
  \___/|_| |_|_|\__\___|""")
 print("\n****************************************************************")
 print("\n* Copyright of Unite, 2024                              *")
 print("\n* Email : as9034731066@gmail.com                               *")
 #print("\n* https://www.youtube.com/davidbombal                          *")
 print("\n****************************************************************")

api_key = '57e3de8428a9e14885e553719f4800e738d2150b1058e51ee9b1dc0b9b0a044d'

 
url_to_scan = input("Enter the Url to be Scanned without 'https://' Like: 'www.example.com' :")
if not is_valid_url(url_to_scan):
            print("Invalid URL format. ")
else:
    pdf_filename = pdf_filename = clean_filename(url_to_scan)
    virustotal_scan(api_key, url_to_scan, pdf_filename)
