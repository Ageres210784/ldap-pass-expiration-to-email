#!/usr/bin/env python3
import ldap
from datetime import datetime, timedelta
import smtplib
from email.mime.text import MIMEText
import os

def send_email(recipient, message):
  sender = os.getenv("EMAIL_LOGIN", default=None)
  password = os.getenv("EMAIL_PASSWORD", default=None)

  server = smtplib.SMTP(os.getenv("EMAIL_SMTP_ADDR", default="smtp.gmail.com"), os.getenv("EMAIL_SMTP_PORT", default=587))
  server.starttls()

  try:
    server.login(sender, password)
    msg = MIMEText(message)
    msg["Subject"] = "Update your password!"
    server.sendmail(sender, recipient, msg.as_string())
    return f"The message was sent seccessfully!"

  except Exception as _ex:
    return f"{_ex}\nCheck your login and password please!"

def main():

  ldapUrl = os.getenv("LDAP_URL", default="ldap://ldap:389")
  rootDn = os.getenv("LDAP_ROOT_DN", default="dc=example,dc=com")
  bindDn = os.getenv("LDAP_BIND_DN", default="cn=reader," + rootDn)
  bindPw = os.getenv("LDAP_BIND_PW", default="readonlypassword")
  base = os.getenv("LDAP_BASE", default="ou=users," + rootDn)
  scope = ldap.SCOPE_SUBTREE
  filterExp = os.getenv("LDAP_FILTER_EXP", default="(&(objectClass=posixAccount)(pwdChangedTime=*)(mail=*)(!(pwdAccountLockedTime=*)))")
  attrList = ["uid", "mail", "pwdChangedTime"]
  alertTime = int(os.getenv("PASSWD_ALERT_TIME", default=259200)) #3 days

  oldap = ldap.initialize(ldapUrl)
  oldap.simple_bind_s(bindDn,bindPw)
  results = oldap.search_s(base, scope, filterExp, attrList)
  pwdMaxAge = timedelta(seconds=int(oldap.search_s("cn=default,ou=pwPolicies," + rootDn, ldap.SCOPE_BASE)[0][1]['pwdMaxAge'][0]))
  for result in results:
    # userDn = result[0]
    userUid = result[1]['uid'][0].decode('utf-8')
    userMail = result[1]['mail'][0].decode('utf-8')
    pwChangedTime = datetime.strptime(result[1]['pwdChangedTime'][0].decode('utf-8')[:-1], "%Y%m%d%H%M%S")
    userRemPwdLifetime = pwdMaxAge - (datetime.utcnow() - pwChangedTime)
    if userRemPwdLifetime.total_seconds() < alertTime:
      send_email(userMail, f"Your account ({userUid}) password will expire in {userRemPwdLifetime.days} days!")
  oldap.unbind_s

if __name__ == "__main__":
  main()
