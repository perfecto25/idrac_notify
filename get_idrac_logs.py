#!/usr/bin/env python
from __future__ import print_function
import sys
import os
import yaml
import arrow
import logging
import requests
from requests.exceptions import SSLError
import jinja2
import smtplib
import socket
from email.message import EmailMessage
from dictor import dictor
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

with open("config.yaml", 'r') as stream:
    try:
        config = yaml.safe_load(stream)
    except yaml.YAMLError as exc:
        print(exc)
        sys.exit()
        
log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)
handler = logging.FileHandler('idrac.log')
formatter = logging.Formatter('[%(levelname)s] %(asctime)s >> %(message)s')
handler.setFormatter(formatter)
log.addHandler(handler)

notif_emails = dictor(config, 'notif_emails')
from_addr = dictor(config, 'from_addr', 'alerts@company.com')
smtp_host = dictor(config, 'smtp_host', 'localhost')
local_tz = dictor(config, 'local_tz', 'America/New_York')
check_cycle = dictor(config, 'check_cycle', 6)
hosts = dictor(config, 'hosts', checknone=True)
user = dictor(config, 'user', checknone=True)
password = dictor(config, 'password', checknone=True)
header = {'Content-Type':'application/json'}

def send_email(to_addr, from_addr, smtp_host, cc=None, bcc=None, subject=None, body=None):
    
    if not to_addr or not from_addr:
        log.error('error sending email, To or From values are null')
        return 'error'

    # convert TO into list if string
    if type(to_addr) is not list:
        to_addr = to_addr.split()

    to_list = to_addr + [cc] + [bcc]
    to_list = filter(None, to_list) # remove null emails

    msg = EmailMessage()
    msg['From']    = from_addr
    msg['Subject'] = subject
    msg['To']      = ','.join(to_addr)
    msg['Cc']      = cc
    msg['Bcc']     = bcc
    msg.set_content(body, 'html')
    try:
        s = smtplib.SMTP(smtp_host)
    except smtplib.SMTPAuthenticationError as e:
        log.error('Error authetnicating to SMTP server: %s, exiting.., %s' % (smtp_host, str(e)))
        return 'error'
    except socket.timeout:
        log.error('SMTP login timeout')
        return 'error'
        
    try:
        s.send_message(msg)
    except smtplib.SMTPException as e:
        log.error('Error sending email')
        log.error(str(e))
    finally:
        s.quit()
        
def err_handler(function):
    ''' error handling wrapper for set of actions '''
    try:
        function()
    except Exception as err:
        log.error("Problem running function: %s" % function.__name__)
        log.exception(str(err))
        raise
        
def render_template(template, **kwargs):
    ''' renders a Jinja template into HTML '''
    # check if template exists
    if not os.path.exists(template):
        log.error('No template file present: %s' % template)
        return 'error'

    templateLoader = jinja2.FileSystemLoader(searchpath="/")
    templateEnv = jinja2.Environment(loader=templateLoader)
    templ = templateEnv.get_template(template)
    return templ.render(**kwargs)
    
def get_logs(ip):
    ''' contacts iDrac host and gets System Event logs '''
    url = 'https://{}/redfish/v1/Managers/iDRAC.Embedded.1/Logs/Sel'.format(ip)
    try:
        req = requests.get(url, auth=(user, password), verify=False)
        req.raise_for_status()
        return req.json()
    except SSLError as err:
        pass

def check_logs(host):
    ''' parses System Event log and checks for Warnings or Errors, emails if found '''
    ip = (dictor(config, 'hosts.{}'.format(host), checknone=True))
    logdump = get_logs(ip)

    event_dict = {}
    
    if dictor(logdump, 'Members'):
        for event in dictor(logdump, 'Members'):

            # get Warnings or Errors only
            if not event['Severity'].upper() == 'OK':
                # actual timestamp of event in remote timezone
                idrac_raw = arrow.get(event['Created'])
                idrac_event = idrac_raw.to(local_tz).format('YYYY-MM-DD HH:mm:ss')
                idrac_event = arrow.get(idrac_event, 'YYYY-MM-DD HH:mm:ss')

                # actual current time right now
                now = arrow.now(dictor(config, 'local_tz')).format('YYYY-MM-DD HH:mm:ss')
                now = arrow.get(now, 'YYYY-MM-DD HH:mm:ss')

                # check if errors/warnings are old or brand new
                diff = idrac_event - now
                days = diff.days
                hours, remainder = divmod(diff.seconds, 3600) # Get difference hour

                # latest events that happened today
                if abs(days) == 0:

                    # log the errors
                    log.warning('ALERT: iDrac Error or Warning detected..')
                    log.warning('iDrac instance: %s' % host)
                    log.warning('timestamp (local timezone): %s' % idrac_raw)
                    log.warning('severity: %s' % event['Severity'])
                    log.warning('message: %s' % event['Message'])
                    event_dict[event['Created']] = {"severity": event['Severity'], "message": event['Message']}

    # if non-"OK" events detected, send email alert
    if event_dict:
        html = render_template(os.getcwd()+'/notification.j2', vars=event_dict)
        subject = f'iDRAC Alert: {host}'
        send_email(to_addr=notif_emails, from_addr=from_addr, smtp_host=smtp_host, 
            subject=subject, body=html)

if __name__ == "__main__":

    @err_handler
    def check_idrac_logs():
        for host in hosts:
            log.info('checking logs for idrac: %s' % host)
            check_logs(host)
