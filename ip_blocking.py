#!/usr/bin/env python

import subprocess
import re
import os
import logging

ssh_log_file = "/var/log/auth.log"
mail_log_file = "/var/log/mail.log"
blocked_ips_file = "/etc/hosts.deny"
whitelisted_ips_file = "whitelisted_ips.txt"  # Path to the whitelisted IPs file
log_file = "ip_blocking.log"  # Path to the log file


logging.basicConfig(filename=log_file, level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

def parse_logs(log_file):
    suspicious_ips = []
    try:
        with open(log_file, "r") as file:
            logs = file.readlines()
        for log in logs:
            ip_match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", log)
            if ip_match:
                ip = ip_match.group()
                suspicious_ips.append(ip)
        logging.info(f"Parsed {log_file} successfully")
    except FileNotFoundError:
        logging.error(f"Log file {log_file} not found")
    except Exception as e:
        logging.error(f"Error occurred while parsing {log_file}: {str(e)}")
    return suspicious_ips

def block_ips(ips):
    try:
        with open(blocked_ips_file, "a") as file:
            for ip in ips:
                file.write(f"sshd: {ip}\n")
                file.write(f"sendmail: {ip}\n")
        subprocess.run(["service", "ssh", "restart"])
        subprocess.run(["service", "sendmail", "restart"])
        logging.info("Blocked IPs successfully")
    except PermissionError:
        logging.error("Permission denied while writing to blocked IPs file")
    except Exception as e:
        logging.error(f"Error occurred while blocking IPs: {str(e)}")

def whitelist_ips(ips):
    try:
        with open(whitelisted_ips_file, "a") as file:
            for ip in ips:
                file.write(f"{ip}\n")
        logging.info("Whitelisted IPs successfully")
    except PermissionError:
        logging.error("Permission denied while writing to whitelisted IPs file")
    except Exception as e:
        logging.error(f"Error occurred while whitelisting IPs: {str(e)}")

def check_whitelisted(ip):
    try:
        with open(whitelisted_ips_file, "r") as file:
            whitelisted_ips = file.read().splitlines()
        if ip in whitelisted_ips:
            logging.info(f"IP {ip} is whitelisted")
            return True
    except FileNotFoundError:
        logging.error(f"Whitelisted IPs file {whitelisted_ips_file} not found")
    except Exception as e:
        logging.error(f"Error occurred while checking whitelisted IPs: {str(e)}")
    return False

if __name__ == "__main__":
    try:
        ssh_suspicious_ips = parse_logs(ssh_log_file)
        mail_suspicious_ips = parse_logs(mail_log_file)
        all_suspicious_ips = ssh_suspicious_ips + mail_suspicious_ips
        unique_suspicious_ips = list(set(all_suspicious_ips))

        # Check if IP is whitelisted before blocking
        filtered_ips = [ip for ip in unique_suspicious_ips if not check_whitelisted(ip)]

        block_ips(filtered_ips)
    except Exception as e:
        logging.error(f"An error occurred in the main script: {str(e)}")
