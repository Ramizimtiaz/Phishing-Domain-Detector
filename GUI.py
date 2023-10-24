import tkinter
from tkinter import *

from Checker import Checker


class PhishingDetectorGUI:
    def __init__(self):
        self.root = Tk()
        self.root.title("Phishing domain detector")
        self.root.geometry("400x400")
        self.root.configure(bg="black")
        self.user_input = ""  # Instance variable to store user input
        self.error1 = tkinter.Label(self.root, text="", bg='black')
        self.error1.place(x=10, y=130)
        self.whoisc = tkinter.Label(self.root, text="", bg='black')  # Country Label
        self.whoisc.place(x=10, y=150)
        self.whoisd = tkinter.Label(self.root, text="", bg='black') # Domain Registrar label
        self.whoisd.place(x=10, y=170)
        self.creation = tkinter.Label(self.root, text="", bg='black')
        self.creation.place(x=10,y=190)
        self.ssl = tkinter.Label(self.root, text = "", bg= 'black')
        self.ssl.place(x=10,y=210)
        self.http = tkinter.Label(self.root, text = "", bg= 'black')
        self.http.place(x=10,y=230)
        self.redirects = tkinter.Label(self.root, text = "", bg= 'black')
        self.redirects.place(x=10,y=250)
        self.redirects2 = tkinter.Label(self.root, text = "", bg= 'black')
        self.redirects2.place(x=10,y=270)
        self.sus = tkinter.Label(self.root, text="", bg='black')
        self.sus.place(x=10, y=290)
        self.check1 = tkinter.Label(self.root, text="", bg='black')

        Label(self.root, text="Welcome Please input URL below", font=("Arial", 13, "bold"), fg="lightblue",
              bg="black").place(x=60, y=15)

        self.entry_widget = Entry(self.root, width=30)
        self.entry_widget.place(x=100, y=50)

        Button(self.root, text="Submit", font=("Arial", 13, "bold"), command=self.retrieve_input, fg="green").place(
            x=150, y=80)

    def retrieve_input(self):
        self.user_input = self.entry_widget.get()
        checker = Checker()
        checker.check_url(self.user_input, self)
        checker.check_http(self.user_input, self)
        checker.whois_data(self.user_input, self)
        checker.check_requests(self.user_input, self)
        checker.get_date_before_expired(self.user_input.split("//")[-1].split("/")[0], self)
        checker.sus(self.user_input,self)

    def run(self):
        self.root.mainloop()

    def get_user_input(self):
        return self.user_input
