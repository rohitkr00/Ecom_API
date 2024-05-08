from my_task.celery import app
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from random import randint

from django.conf import settings



def sendemail(email):
	try:
		message = """
					<html>
					<body>
					<h1>Hello this is your sales report</h1>
					<hr>
					<h3>There is nothing to show</h3>
					<br>
					<h2>Thank You</h2>
					</body>
					</html>"""
		msg=MIMEMultipart()
		msg['Subject'] = "Login otp"
		msg['From'] = "manankr21@gmail.com"
		msg['To'] = email
		msg.attach(MIMEText(message,'html'))

		smtp = smtplib.SMTP(host='smtp.gmail.com',port=587)
		smtp.starttls()
		smtp.login("manankr21@gmail.com","vqhqptiyzcsavkbn")
		smtp.send_message(msg)
		smtp.quit()
		return True

	except Exception as ex:
		print("Mail send Error : ",ex)
		return False



@app.task(name="send_notification")
def send_notification():
        subject = "subject"
        message = "Your account is verified"
        email_from = settings.EMAIL_HOST_USER
        recipient_list = "rohitkumarbxr243@gmail.com"
        return sendemail(recipient_list)
        
      


