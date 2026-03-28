import json
import pprint
import pathlib
import os,os.path
import sys
import re
import glob
from pathlib import Path
from collections import defaultdict


def get_user_auth_times(user_id):
    """
    Returns a list of the date and time of logins for user userid from log/auth.log.x
    """
    
    # Make a variable called folder path and pattern
    folder_path = "C:/Users/titag/github-classroom/tu-cyb-2004-fa25/project-1-network-log-analysis-bradley-untamed/log"
    file_pattern = "auth.log.*"
    
    # Use glob to find all files matching the pattern inside the folder path
    full_pattern = os.path.join(folder_path, file_pattern)
    file_paths = glob.glob(full_pattern)

    # Create a for function to go through the files in the log folder and get the times and dates
    # for a successfull login for a user_id
    
         
    # Check to ensure that the files are found so that the program does not crash
    if not file_paths:
        print(f"ERROR: No files found matching '{full_pattern}'")
        print("Please ensure the folder path and file pattern are correct.")
        return []

    # Initialize the list to store all timestamps
    all_login_timestamps = []

    # Use the re.escape to protect the user_id string if it contains special regex characters
    log_pattern = re.compile(
        # Match  systemd-logind
        rf"systemd-logind\[\d+\]:\s+"

        # Match the message including the session ID
        rf"New session \d+ of user {re.escape(user_id)}.",

        # Use IGNORECASE for robustness against case variations in user_id or log source
        re.IGNORECASE
    )

    # Use a 'for' loop to iterate over every full file path
    for full_file_path in file_paths:    
        file_name = os.path.basename(full_file_path)
        
        # Check to ensure that the file path exists
        if not os.path.isfile(full_file_path):
            print(f"\nFile Skipped: {file_name} - File not found or is a directory.")
            continue

        # Initialize the list to store all timestamps
        file_timestamps = []
        
        # Read the file line by line
        with open(full_file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                
                # Search for the pattern in each line
                if log_pattern.search(line):
                    timestamp = line[:15]
                    # File timestamp holds the captured date and time string
                    file_timestamps.append(timestamp)
        
        # Append the file timestamps to all login timestamps
        if file_timestamps:
            all_login_timestamps.extend(file_timestamps)

    return all_login_timestamps


# Get all user ids that are failed logins with invalid user names. Return a dictionary mapping the userid to the number of invalid attempts
def get_invalid_logins():
    """
    Returns a dictionary mapping invalid user ids to # of failed logins on log/auth.log.x
    """
    
    # Make a variable called folder path and pattern
    folder_path = "C:/Users/titag/github-classroom/tu-cyb-2004-fa25/project-1-network-log-analysis-bradley-untamed/log"
    file_pattern = "auth.log.*"
    
    # Use glob to find all files matching the pattern inside the folder path
    full_pattern = os.path.join(folder_path, file_pattern)
    file_paths = glob.glob(full_pattern)

    # Create a for function to go through the files in the log folder and get the times and dates
    # for a successfull login for a user_id
    
         
    # Check to ensure that the files are found so that the program does not crash
    if not file_paths:
        print(f"ERROR: No files found matching '{full_pattern}'")
        return {}

    # Create a variable invalid login counts to count all logins and to accept only integers
    invalid_login_counts = defaultdict(int)

    # Match "Invalid user" followed by any non-whitespace sequence (more flexible than \w+)
    pattern = re.compile(r"Invalid user ([^\s]+)", re.IGNORECASE)

    # Use a 'for' loop to iterate over every full file path
    for full_file_path in file_paths:
        
        # Check to ensure that the file path exists
        if not os.path.isfile(full_file_path):
            continue

        # Read the file line by line
        with open(full_file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                
                # Search for the pattern in each line
                if pattern.search(line):
                    
                    # Extract the captured user ID from the regex match (the string after "Invalid user")
                    user_id = pattern.search(line).group(1)
                    invalid_login_counts[user_id] += 1

    return dict(invalid_login_counts)

# Find all IP addresses for invalid logins, then see which IPs are also used for scanning
def compare_invalid_IPs():
    """
    Returns a sorted list of IP addresses that appear both in:
    - Invalid login attempts from auth.log.*
    - Blocked IP entries from ufw.log.*
    """

    # Define the folder containing the log files
    log_folder = "C:/Users/titag/github-classroom/tu-cyb-2004-fa25/project-1-network-log-analysis-bradley-untamed/log"

    # Regex pattern to extract IPs from lines like:
    # "Invalid user jmuthusi from 104.248.152.227"
    auth_pattern = re.compile(r"Invalid user \S+ from (\d+\.\d+\.\d+\.\d+)")

    # Regex pattern to extract IPs from lines like:
    # "SRC=104.248.152.227" in ufw logs
    ufw_pattern = re.compile(r"SRC=(\d+\.\d+\.\d+\.\d+)")

    # Find all auth.log.* files in the log folder
    auth_files = glob.glob(os.path.join(log_folder, "auth.log.*"))

    # Find all ufw.log.* files in the log folder
    ufw_files = glob.glob(os.path.join(log_folder, "ufw.log.*"))

    # Use sets to store unique IPs from each source
    invalid_ips = set()
    blocked_ips = set()

    # Loop through each auth log file to extract IPs from invalid login attempts
    for file_path in auth_files:
        
        # Read the file line by line
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
               
                # Search for the pattern in each line
                if auth_pattern.search(line):
                    
                    # Add the captured IP address to the invalid_ips set
                    invalid_ips.add(auth_pattern.search(line).group(1))

    # Loop through each ufw log file to extract blocked IPs
    for file_path in ufw_files:
        # Read the file line by line
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                
                # Search for the pattern in each line
                if ufw_pattern.search(line):

                    # Add the captured IP address to the blocked_ips set
                    blocked_ips.add(ufw_pattern.search(line).group(1))

    # Find the intersection of both sets — IPs that are both invalid and blocked
    common_ips = invalid_ips.intersection(blocked_ips)

    # Print the result as a sorted list for readability
    print(common_ips)



if __name__=="__main__":
    
    print(get_user_auth_times("tmoore"))
    print(get_invalid_logins())
    compare_invalid_IPs()
    #extract_log_files("ufw.log")
    #extract_log_files("auth.log")
    
