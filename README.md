# Network-monitoring

This tool will monitor multiple targets, check network protocols, log results over time, and send alerts when issues arise. This example uses additional Python libraries: scapy for packet sniffing and analysis, and smtplib for sending alert emails.

## Import necessary librarys.

```python
import os
import time
import logging
from scapy.all import sniff, IP
import smtplib
from email.mime.text import MIMEText
```

## Specify the Targets and Set Up Logging

```python
targets = ['192.168.1.1', '192.168.1.2', '192.168.1.3']
logging.basicConfig(filename='network_monitor.log', level=logging.INFO)
```


## Create Function and Send Email Alerts
```python
def send_alert(target):
    msg = MIMEText(f'Target {target} is down!')
    msg['Subject'] = 'Network Alert'
    msg['From'] = 'monitor@example.com'
    msg['To'] = 'admin@example.com'
    s = smtplib.SMTP('localhost')
    s.send_message(msg)
    s.quit()
```
## Create Monitoring Function
```python
def monitor_target(target):
    response = os.system("ping -c 1 " + target + " > /dev/null 2>&1")
    if response == 0:
        logging.info(f'{time.asctime()} - {target} is up.')
    else:
        logging.warning(f'{time.asctime()} - {target} is down.')
        send_alert(target)
```

## Create Packet Sniffing Function

```python
def packet_sniff(pkt):
    if IP in pkt:
        ip_src=pkt[IP].src
        ip_dst=pkt[IP].dst
        print(f'IP Packet: {ip_src} is going to {ip_dst}')
```

## Main Loop

```python
while True:
    for target in targets:
        monitor_target(target)
    sniff(prn=packet_sniff, filter="ip", store=0, count=10)
    time.sleep(5)
```


The monitor_target function checks whether each target is up or down and logs the results. If a target is down, it also sends an alert email.

The packet_sniff function is called by the sniff function from the scapy library to analyze network traffic. In this case, it simply prints out the source and destination of each IP packet, but it could be extended to perform more complex analysis.

The main loop continuously cycles through the targets and checks their status, then analyzes a few packets of network traffic, and then waits for 5 seconds before starting the cycle again.
