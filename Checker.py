import requests as re
import requests
from datetime import datetime, timedelta
import socket
import ssl
import GUI
import time
from bs4 import BeautifulSoup
from whois import whois


class Checker:
    gui = GUI

    def __init__(self):
        pass

    def check_url(self, url, gui_instance):
        try:
            response = re.get(url)
            if (response.status_code >= 400) & (response.status_code <= 499):
                gui_instance.error1.config(text="Url is invalid", fg='red', font=("Arial", 13, "bold"), bg='black')
            elif (response.status_code >= 500) & (response.status_code <= 599):
                gui_instance.error1.config(text="Server Error", fg='red', font=("Arial", 13, "bold"), bg='black')
            elif (response.status_code >= 200) & (response.status_code < 299):
                gui_instance.error1.config(text="Url is valid", fg='lightgreen', font=("Arial", 13, "bold"), bg='black')
                soup = BeautifulSoup(response.text, 'html.parser')
                for link in soup.find_all('a'):
                    print(link.get('href'))
            else:
                print(f"Failed to retrieve the webpage. Status code: {response.status_code}")

        except:
            print("An exception occurred")
            gui_instance.error1.config(text="Please put a proper URL", fg='darkred', font=('Arial', 10, 'bold'),
                                       bg='black')

    def whois_data(self, url, gui_instance):
        try:
            res = whois(url)
            country = res.get("country")
            registrar = res.get("registrar")
            gui_instance.whoisc.config(text=("Domain is registered in the", country), fg='pink',
                                       font=("Arial", 10, "bold"), bg='black')
            gui_instance.whoisd.config(text=("Domain is registered with", registrar), fg='pink',
                                       font=("Arial", 10, "bold"), bg='black')
            creation_date = self.extract_date(res.get("creation_date"))

            # Check if the result is a datetime object
            if not isinstance(creation_date, datetime):
                print("Error: Expected a datetime object for creation date.")
                return

            print("Creation date:", creation_date)

            # Current date
            t = time.localtime()
            current_date = datetime(t.tm_year, t.tm_mon, t.tm_mday)

            # Calculate the difference in days
            days_diff = (current_date - creation_date).days

            if days_diff <= 90:
                gui_instance.creation.config(text=("Domain Created Recently", registrar), fg='red',
                                             font=("Arial", 10, "bold"), bg='black')
            else:
                gui_instance.creation.config(text=("Domain creation date looks good", creation_date), fg='lightgreen',
                                             font=("Arial", 10, "bold"), bg='black')

        except Exception as e:
            print(f"Error: {e}")

    def extract_date(self, whois_date):
        if isinstance(whois_date, list):
            return whois_date[0]
        return whois_date

    def check_http(self, url, gui_instance):
        print(f"Checking URL for 'http': {url}")  # debug print
        if url.startswith('http://'):
            gui_instance.http.config(text="This Url is http this means that is website is unsafe:", fg='red',
                                     font=("Arial", 10, "bold"), bg='black')
        else:
            gui_instance.http.config(text="This Url is HTTPS meaning data is encrypted", fg='lightgreen',
                                     font=("Arial", 10, "bold"), bg='black')

    def get_date_before_expired(self, hostname, gui_instance, port='443'):
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert_info = ssock.getpeercert()
                expiry_date = datetime.strptime(cert_info['notAfter'], '%b %d %H:%M:%S %Y %Z')
                print(expiry_date)
                print(expiry_date)
                expiry = str(expiry_date)
                year = int(expiry[0:4])
                month = int(expiry[5:7])
                day = int(expiry[8:10])
                t = time.localtime()
                current_year = t.tm_year
                current_month = t.tm_mon
                current_day = t.tm_mday
        if year > current_year:
            gui_instance.ssl.config(text=("SSL certificate looks good, expires on:", expiry), fg='lightgreen',
                                    font=("Arial", 10, "bold"), bg='black')
        elif (year == current_year) & (month > current_month):
            gui_instance.ssl.config(text=("SSL certificate looks good, expires on:", expiry), fg='lightgreen',
                                    font=("Arial", 10, "bold"), bg='black')
        elif (year == current_year) & (month == current_month) & (day > current_day):
            gui_instance.ssl.config(text=("SSL certificate looks good, expires on:", expiry), fg='lightgreen',
                                    font=("Arial", 10, "bold"), bg='black')
        else:
            gui_instance.ssl.config(text=("SSL Expired", expiry), fg='red',
                                    font=("Arial", 10, "bold"), bg='black')

    def check_requests(self, url, gui_instance):
        response = requests.get(url)
        if response.history:
            gui_instance.redirects.config(text="Redirection detected", fg='red',
                                          font=("Arial", 10, "bold"), bg='black')
            for resp in response.history:
                print(resp.status_code, resp.url)
            print("Final destination:", response.url)
        else:
            print("The request was not redirected.")
            response = requests.get(url, allow_redirects=False)

        if response.status_code in (300, 301, 302, 303, 307, 308):
            gui_instance.redirects2.config(text=("Redirection detected! The HTTP status code is:", response.status_code,
                                                 "\nRedirection detected! The HTTP status code is:",
                                                 response.headers['Location'])
                                           , fg='green', font=("Arial", 10, "bold"), bg='red')

        else:
            gui_instance.redirects.config(text="No redirects detected", fg='lightgreen',
                                          font=("Arial", 10, "bold"), bg='black')

    def sus(self, url, gui_instance):
        suspicious_chars = ['<', '>', '"', "'", '(', ')', '{', '}', '[', ']', '@', '!', '#', '$', '%', '^', '&', '*',
                            '`', '|', '\\', '/', ' ', 'xn--']

        for char in suspicious_chars:
            if char in url:
                gui_instance.redirects.config(text="Suspicious Characters in the Url", fg='red',
                                              font=("Arial", 10, "bold"), bg='black')
                return
        gui_instance.redirects.config(text="No suspicious characters detected", fg='light',
                                      font=("Arial", 10, "bold"), bg='black')
