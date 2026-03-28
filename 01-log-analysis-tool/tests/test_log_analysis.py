import pytest
import log_analysis
from pathlib import Path

def test_get_user_auth_times():
    auth_dates = log_analysis.get_user_auth_times("tmoore")
    assert 'Feb 17 11:57:22' in auth_dates
    assert 'Feb 17 12:11:52' in auth_dates
    assert 'Feb 17 13:28:25' in auth_dates

def test_get_invalid_logins():
    test_invalid_logins = log_analysis.get_invalid_logins()
    assert test_invalid_logins['user001'] == 1
    assert test_invalid_logins['humphrey'] == 1
    assert test_invalid_logins['Administrator'] == 11
    assert test_invalid_logins['apache'] == 45
    assert test_invalid_logins['admin'] == 1380

def test_extract_log_files():
    log_analysis.extract_log_files("ufw.log")
    log_analysis.extract_log_files("auth.log")
    assert Path('./log/auth.log.all').exists()

    with open('log/auth.log.all', 'r') as f:
        log_all = len(f.readlines())
    with open('log/auth.log.1', 'r') as f:
        log_1 = len(f.readlines())
    with open('log/auth.log.2', 'r') as f:
        log_2 = len(f.readlines())
    with open('log/auth.log.3', 'r') as f:
        log_3 = len(f.readlines())
    with open('log/auth.log.4', 'r') as f:
        log_4 = len(f.readlines())
    assert log_all == log_1 + log_2 + log_3 + log_4


def test_compare_invalid_IPs():
    matched_ips = log_analysis.compare_invalid_IPs()
    # assert matched_ips == {'95.111.235.212', '64.62.197.122', '64.62.197.62', '147.182.244.135', '141.98.10.81', '64.62.197.2', '129.244.0.252', '188.166.255.101', '107.189.31.191', '65.49.20.69', '45.153.160.139', '106.12.222.80', '64.62.197.182', '65.49.20.66', '104.248.168.145', '179.43.187.173', '157.230.108.36', '2.57.122.107', '165.22.85.106', '179.43.170.172', '43.154.1.130', '67.205.138.198', '141.98.10.202', '45.9.20.25', '167.71.79.19', '198.98.51.76', '139.135.229.24', '45.9.20.73', '141.98.10.179', '179.43.139.10', '179.43.170.170', '65.49.20.67', '64.62.197.212', '64.62.197.32', '198.98.49.221', '164.90.227.119', '178.73.215.171', '179.43.159.4', '142.93.48.117', '45.125.65.126', '164.90.156.240', '31.7.57.130', '128.199.13.112', '206.81.30.225', '141.98.11.22', '43.154.1.155', '43.154.40.120', '141.98.11.23', '179.43.159.3', '65.49.20.68', '141.98.10.206'}
    assert '128.199.13.112' in matched_ips
    assert '164.90.156.240' in matched_ips
    assert '188.166.255.101' in matched_ips
    assert '141.98.10.81' in matched_ips
    assert '141.98.11.23' in matched_ips
