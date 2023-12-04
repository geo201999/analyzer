# Project Analyzer

## Overview

The Project Analyzer is a Python script designed for the analysis of hashes, IPs, and domains, utilizing three different APIs: X-Force, VirusTotal, and Fraudguard. Additionally, it integrates the NIST API to perform searches based on Common Vulnerabilities and Exposures (CVE).

## Prerequisites

Before using the script, ensure you have Python 3 installed on your system. You can install the required `requests` library by running the following command:


pip install requests


## APIs and Usage Limits

### 1. X-Force API

The X-Force API allows a maximum of 135 requests per month. Ensure you stay within this limit to avoid service disruptions. You can obtain your API key from the X-Force platform.

### 2. VirusTotal API

The VirusTotal API has a monthly limit of 500 requests, with a rate limit of 4 requests per minute. Exceeding these limits may result in temporary suspension. Obtain your API key from the VirusTotal website.

### 3. Fraudguard API

Provide the necessary credentials for the Fraudguard API. Refer to the official documentation for information on usage limits and obtaining API keys.

### 4. NIST CVE API

The NIST CVE API is integrated for CVE searches. Ensure you have the required access and permissions to use the NIST API.

## Script Usage

1. Clone the repository:

    
    git clone https://github.com/geo201999/analyzer.git
    cd repository
    

2. Open the script in your preferred text editor and add the API keys and credentials for X-Force, VirusTotal, and Fraudguard.

3. Run the script:

   
    python main.py
  

## Note

- **Caution:** Be mindful of the usage limits for each API to prevent service disruptions.
- **Security:** Ensure that your API keys and credentials are kept secure and not shared publicly.
- **Contribution:** Feel free to contribute to the project by submitting pull requests or reporting issues.

## License

This project is licensed under the [MIT License](LICENSE).

## Acknowledgments

- Special thanks to the developers of X-Force, VirusTotal, Fraudguard, and NIST for providing powerful APIs for cybersecurity analysis.

##
Developed by Geovanni Munoz Otarola

Happy analyzing!
