import random
import string
import datetime
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Function to send OTP via email
def send_otp(email, otp):
    sender_email = 'ranjithpachamuthu003@gmail.com'  
    sender_password = 'cjgq atpf cqni tzqm'

    msg = MIMEText(f'Your OTP is: {otp}')
    msg['Subject'] = 'OTP for Signup'
    msg['From'] = sender_email
    msg['To'] = email

    server = smtplib.SMTP_SSL('smtp.gmail.com', 465)
    server.login(sender_email, sender_password)
    server.sendmail(sender_email, [email], msg.as_string())
    server.quit()

# Function to generate OTP
def generate_otp():
    return ''.join(random.choices(string.digits, k=6))
