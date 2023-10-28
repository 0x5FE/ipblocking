# Features

- Parses SSH and mail logs to identify suspicious IP addresses.
  
- Blocks suspicious IP addresses by adding entries to the ***/etc/hosts.deny***file for both SSH and Sendmail services.
  
- Whitelists specific IP addresses by adding them to the ***whitelisted_ips.txt file.***

- Logs its activities in a file named ***ip_blocking.log.***

# Installation

- Clone the script from a GitHub repository or download the script to this directory.

- Ensure that you have Python installed on your system.
  
- Create a directory for the script and navigate to it.

      mkdir ipblocking

      cd ipblocking

- Create a Python virtual environment (optional but recommended).

      python -m venv venv
    
      source venv/bin/activate


- Install any required Python packages using pip.

      pip install subprocess


- Configure the script by modifying the ***ssh_log_file***, ***mail_log_file***, ***blocked_ips_file***, ***whitelisted_ips_file***, and ***log_file*** variables at the top of the script to match your system configuration.


# Configuration

- You can configure the script by modifying the following variables at the beginning of the script:
  
    - ***ssh_log_file:*** Path to the SSH log file (default: "/var/log/auth.log").
  
    - ***mail_log_file:*** Path to the mail log file (default: "/var/log/mail.log").
  
    - ***blocked_ips_file:*** Path to the hosts.deny file for blocking IPs (default: "/etc/hosts.deny").
  
    - ***whitelisted_ips_file:*** Path to the whitelisted IPs file (default: "whitelisted_ips.txt").
  
    - ***log_file:*** Path to the log file (default: "ip_blocking.log").



# Usage

  - Navigate to the directory where the script is located.
  
  - Activate the virtual environment (if used) with source ***venv/bin/activate.***
  
  Run the script using the following command:
  
  `python ip_blocking.py`
  
- The script will parse the log files, block suspicious IP addresses, and log its activities.

# Possible Problems and Solutions

***Log File Not Found***

- If the script cannot find the log files specified in ***ssh_log_file or mail_log_file***, it will log a ***"Log file not found" error.***

- Solution: Ensure that the specified log files exist at the given paths or update the ***ssh_log_file and mail_log_file variables*** to point to the correct log file paths.

***Permission Denied***

- If the script encounters a permission denied error while writing to the ***blocked_ips_file*** or ***whitelisted_ips_file***, it logs a ***"Permission denied" error.***
  
- Solution: Make sure the script has the necessary permissions to write to the specified files. You may need to run the script with administrative privileges or adust the file permissions.


