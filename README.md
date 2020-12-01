# IDRAC Log Monitoring

uses RedFish API to monitor every physical iDrac server (need IDRAC version 7 and up)

if iDrac logs a warning or an error, this script will email and log the warning

Script is scheduled via cron to run at chosen intervals  



## Requirements
1. Linux OS (Fedora, Centos, Ubuntu)
1. Python 3.6 or greater
1. python-pip (yum install python-pip)

## Setup
install pipenv
    
    pip install --user pipenv

clone this project and install dependencies

    git clone git@github.com:perfecto25/idrac_notify.git
    
    cd idrac_notify
    
    pipenv install

---

## Configure

open up config.yaml and update your host IDRAC IPs

also update read-only user name and password (this account has to be created on each IDRAC - read only account)

---
    
## idrac error check every 6 hrs
    
    0 */6 * * *  cd /opt/idrac_notify && pipenv run idrac_notify

also update config.yaml (check_cycle variable)

---

## Sample Alert

sample email alert

```
iDRAC Alert: nyweb1
Inbox

alert@company.com
Sat, Jul 18, 6:00 PM
to infraalerts, None

iDRAC Alert
Time of event (local timezone): 2020-07-18T20:57:20-05:00
Severity: Critical
Message: The power input for power supply 2 is lost.

```