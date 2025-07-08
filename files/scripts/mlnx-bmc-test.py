#!/usr/bin/env python3


import sonic_platform
import sys
import os
import argparse
import time
import tqdm
import subprocess
from sonic_py_common.logger import Logger


logger = Logger()
logger.set_min_log_priority_info()


def validate_positive_int(value):
    ivalue = int(value)
    if ivalue <= 0:
        raise argparse.ArgumentTypeError(f"{value} is not a positive integer")
    return ivalue


def ping(host):
    """Check if host is reachable via ping"""
    command = ['/usr/bin/ping', '-c', '1', '-W', '1', host]
    try:
        subprocess.check_output(command, stderr=subprocess.STDOUT)
        return True
    except subprocess.CalledProcessError:
        return False


def is_host_reachable(host, timeout):
    """Wait for host to become reachable"""
    start_time = time.time()
    while time.time() - start_time < timeout:
        if ping(host):
            return True
        time.sleep(1)
    return False


def test_bmc_login(bmc, timeout=30):
    """Test BMC login API with retry logic"""
    print("\n=== Testing BMC Login ===")
    print(f"Attempting to login to BMC with {timeout}s timeout...")
    
    start_time = time.time()
    
    while time.time() - start_time < timeout:
        ret = bmc.login()
        print(f"Login attempt result: {ret}")
        
        if ret == 0:
            print("V BMC login successful")
            token = bmc.get_login_token()
            print(f"BMC token: {token[:20]}..." if token else "No token received")
            return True
        else:
            print(f"X BMC login failed (retry in 1s)")
            time.sleep(1)
    
    print(f"X BMC login failed after {timeout}s timeout")
    return False


def test_bmc_logout(bmc):
    """Test BMC logout API"""
    print("\n=== Testing BMC Logout ===")
    print("Attempting to logout from BMC...")
    
    ret = bmc.logout()
    print(f"Logout result: {ret}")
    
    if ret == 0:
        print("V BMC logout successful")
    else:
        print("X BMC logout failed")
    
    return ret == 0


def test_get_bmc_login_user(bmc):
    """Test get BMC login user API"""
    print("\n=== Testing Get BMC Login User ===")
    
    try:
        user = bmc.get_login_user()
        print(f"V BMC login user: {user}")
        return True
    except Exception as e:
        print(f"X Failed to get BMC login user: {e}")
        return False


def test_get_bmc_ip_addr(bmc):
    """Test get BMC IP address API"""
    print("\n=== Testing Get BMC IP Address ===")
    
    try:
        ip_addr = bmc.get_ip_addr()
        print(f"V BMC IP address: {ip_addr}")
        return True
    except Exception as e:
        print(f"X Failed to get BMC IP address: {e}")
        return False


def test_get_bmc_eeprom_list(bmc):
    """Test get BMC EEPROM list API"""
    print("\n=== Testing Get BMC EEPROM List ===")
    
    try:
        ret, eeprom_list = bmc.get_eeprom_list()
        print(f"Get EEPROM list result: {ret}")
        
        if ret == 0:
            print(f"V BMC EEPROM list retrieved successfully")
            print(f"EEPROM entries: {len(eeprom_list)}")
            for eeprom_id, eeprom_data in eeprom_list:
                print(f"  - EEPROM ID: {eeprom_id}")
                print(f"    Data: {eeprom_data}")
            return True
        else:
            print(f"X Failed to get BMC EEPROM list: {eeprom_list}")
            return False
    except Exception as e:
        print(f"X Exception getting BMC EEPROM list: {e}")
        return False


def test_get_bmc_eeprom_info(bmc, eeprom_id):
    """Test get BMC EEPROM info API"""
    print("\n=== Testing Get BMC EEPROM Info ===")
    
    if not eeprom_id:
        print("X No EEPROM ID provided, skipping get BMC EEPROM info test")
        return False
    
    try:
        print(f"Getting EEPROM info for ID: {eeprom_id}")
        ret, eeprom_data = bmc.get_eeprom_info(eeprom_id)
        print(f"Get EEPROM info result: {ret}")
        
        if ret == 0:
            print(f"V BMC EEPROM info retrieved successfully")
            print(f"EEPROM data: {eeprom_data}")
            return True
        else:
            print(f"X Failed to get BMC EEPROM info: {eeprom_data}")
            return False
    except Exception as e:
        print(f"X Exception getting BMC EEPROM info: {e}")
        return False


def test_get_bmc_firmware_list(bmc):
    """Test get BMC firmware list API"""
    print("\n=== Testing Get BMC Firmware List ===")
    
    try:
        ret, fw_list = bmc.get_firmware_list()
        print(f"Get firmware list result: {ret}")
        
        if ret == 0:
            print(f"V BMC firmware list retrieved successfully")
            print(f"Firmware entries: {len(fw_list)}")
            for fw_id, fw_version in fw_list:
                print(f"  - Firmware ID: {fw_id}")
                print(f"    Version: {fw_version}")
            return True
        else:
            print(f"X Failed to get BMC firmware list: {fw_list}")
            return False
    except Exception as e:
        print(f"X Exception getting BMC firmware list: {e}")
        return False


def test_get_bmc_firmware_version(bmc, fw_id):
    """Test get BMC firmware version API"""
    print("\n=== Testing Get BMC Firmware Version ===")
    
    if not fw_id:
        print("X No firmware ID provided, skipping get BMC firmware version test")
        return False
    
    try:
        print(f"Getting firmware version for ID: {fw_id}")
        ret, version = bmc.get_firmware_version(fw_id)
        print(f"Get firmware version result: {ret}")
        
        if ret == 0:
            print(f"V BMC firmware version retrieved successfully")
            print(f"Firmware version: {version}")
            return True
        else:
            print(f"X Failed to get BMC firmware version: {version}")
            return False
    except Exception as e:
        print(f"X Exception getting BMC firmware version: {e}")
        return False


def test_trigger_bmc_debug_log_dump(bmc):
    """Test trigger BMC debug log dump API"""
    print("\n=== Testing Trigger BMC Debug Log Dump ===")
    
    try:
        ret, (task_id, err_msg) = bmc.trigger_bmc_debug_log_dump()
        print(f"Trigger result: {ret}")
        
        if ret == 0:
            print(f"V BMC debug log dump triggered successfully")
            print(f"Task ID: {task_id}")
            return task_id
        else:
            print(f"X Failed to trigger BMC debug log dump: {err_msg}")
            return None
    except Exception as e:
        print(f"X Exception triggering BMC debug log dump: {e}")
        return None


def test_get_bmc_debug_log_dump(bmc, task_id):
    """Test get BMC debug log dump API"""
    print("\n=== Testing Get BMC Debug Log Dump ===")
    
    if not task_id:
        print("X No task ID provided, skipping get BMC debug log dump test")
        return False
    
    try:
        temp_filename = f"bmc_debug_dump_{int(time.time())}.tar.xz"
        temp_path = "/tmp"
        
        print(f"Attempting to get BMC debug log dump with task ID: {task_id}")
        print(f"Target file: {temp_path}/{temp_filename}")
        
        ret, err_msg = bmc.get_bmc_debug_log_dump(task_id, temp_filename, temp_path)
        print(f"Get dump result: {ret}")
        
        if ret == 0:
            print(f"V BMC debug log dump retrieved successfully")
            print(f"File saved to: {temp_path}/{temp_filename}")
            
            full_path = f"{temp_path}/{temp_filename}"
            if os.path.exists(full_path):
                file_size = os.path.getsize(full_path)
                print(f"File size: {file_size} bytes")
            else:
                print("Warning: File not found after successful API call")
            
            return True
        else:
            print(f"X Failed to get BMC debug log dump: {err_msg}")
            return False
    except Exception as e:
        print(f"X Exception getting BMC debug log dump: {e}")
        return False


def test_reset_password(bmc):
    """Test reset password API"""
    print("\n=== Testing Reset Password ===")
    
    try:
        print("Testing password reset for root user...")
        ret = bmc.login()
        if ret != 0:
            print("Failed to login to BMC")
            return False
        user = 'root'
        password = '0penBmcTempPass!'
        
        ret, msg = bmc.change_login_password(password, user)
        print(f"Change password result: {ret}")
        print(f"Message: {msg}")
        
        if ret == 0:
            print("V Root password reset successful")
        else:
            print("X Root password reset failed")
        
        return ret == 0
    except Exception as e:
        print(f"X Exception during password reset: {e}")
        return False


def test_upgrade_bmc_firmware(bmc, fw_image, target=None, timeout=1800):
    """Test BMC firmware upgrade API"""
    print("\n=== Testing BMC Firmware Upgrade ===")
    
    if not os.path.exists(fw_image):
        print(f"X Firmware image file not found: {fw_image}")
        return False
    
    fw_ids = []
    if target:
        fw_ids = [fw_id.strip() for fw_id in target.split(",")]
        print(f'Flashing {fw_image} to {fw_ids}...')
    else:
        print(f'Flashing {fw_image} to BMC...')

    pbar = tqdm.tqdm(total=100)

    def create_progress_callback():
        last_percent = 0

        def callback(percent):
            nonlocal last_percent
            delta = percent - last_percent
            last_percent = percent
            pbar.update(delta)

        return callback

    progress_callback = create_progress_callback()

    start = time.time()

    try:
        if target:
            ret, msg = bmc.update_firmware_on_component(fw_image,
                                                        fw_ids,
                                                        timeout=timeout,
                                                        progress_callback=progress_callback)
        else:
            ret, msg = bmc.update_firmware(fw_image,
                                           timeout=timeout,
                                           progress_callback=progress_callback)

        pbar.close()

        print(f'Time elapsed: {int((time.time() - start) * 10) / 10}s')

        if ret == 0:
            print('V Firmware is successfully updated')
            return True
        else:
            print(f'X Fail to update firmware. {msg}')
            return False
    except Exception as e:
        pbar.close()
        print(f'X Exception during firmware update: {e}')
        return False


def run_api_test(bmc, api_name, **kwargs):
    """Run a specific API test"""
    print(f"\n{'=' * 60}")
    print(f"TESTING API: {api_name.upper()}")
    print(f"{'=' * 60}")
    
    api_tests = {
        'login': lambda bmc: test_bmc_login(bmc),
        'logout': test_bmc_logout,
        'get_user': test_get_bmc_login_user,
        'get_ip': test_get_bmc_ip_addr,
        'get_eeprom_list': test_get_bmc_eeprom_list,
        'get_eeprom_info': lambda bmc: test_get_bmc_eeprom_info(bmc, kwargs.get('eeprom_id')),
        'get_firmware_list': test_get_bmc_firmware_list,
        'get_firmware_version': lambda bmc: test_get_bmc_firmware_version(bmc, kwargs.get('fw_id')),
        'trigger_dump': test_trigger_bmc_debug_log_dump,
        'get_dump': lambda bmc: test_get_bmc_debug_log_dump(bmc, kwargs.get('task_id')),
        'reset_password': test_reset_password,
        'upgrade_firmware': lambda bmc: test_upgrade_bmc_firmware(bmc, kwargs.get('fw_image'), kwargs.get('target')),
    }
    
    if api_name in api_tests:
        return api_tests[api_name](bmc)
    else:
        print(f"X Unknown API test: {api_name}")
        print("Available API tests: login, logout, get_user, get_ip, get_eeprom_list, get_eeprom_info, get_firmware_list, get_firmware_version, trigger_dump, get_dump, reset_password, upgrade_firmware")
        return False


if __name__ == '__main__':

    if os.geteuid() != 0:
        print('Please run under root privilege.')
        sys.exit(-1)

    parser = argparse.ArgumentParser(description='BMC API Test Tool - Run one test at a time')
    parser.add_argument("--test", choices=['login', 'logout', 'get_user', 'get_ip', 'get_eeprom_list', 'get_eeprom_info', 'get_firmware_list', 'get_firmware_version', 'trigger_dump', 'get_dump', 'reset_password', 'upgrade_firmware'],
                        required=True, help="Test a specific BMC API")
    parser.add_argument("--task-id", help="Task ID for get_dump test")
    parser.add_argument("--fw-image", help="Firmware image file for upgrade_firmware test")
    parser.add_argument("--target", help="Target firmware IDs for upgrade (comma-separated)")
    parser.add_argument("--eeprom-id", help="EEPROM ID for get_eeprom_info test")
    parser.add_argument("--fw-id", help="Firmware ID for get_firmware_version test")

    args = parser.parse_args()

    chassis = sonic_platform.platform.Platform().get_chassis()
    bmc = chassis.get_bmc()

    if bmc is None:
        print('X No BMC exists')
        sys.exit(0)

    bmc_ip = bmc.get_ip_addr()
    print(f"BMC IP address: {bmc_ip}")
    
    if not is_host_reachable(bmc_ip, 10):
        print(f'X BMC {bmc_ip} not reachable')
        sys.exit(2)
    
    print(f'V BMC {bmc_ip} is reachable')

    if args.test == 'get_dump' and not args.task_id:
        print("X --task-id is required for get_dump test")
        sys.exit(1)
    
    if args.test == 'upgrade_firmware' and not args.fw_image:
        print("X --fw-image is required for upgrade_firmware test")
        sys.exit(1)

    if args.test == 'get_eeprom_info' and not args.eeprom_id:
        print("X --eeprom-id is required for get_eeprom_info test")
        sys.exit(1)

    if args.test == 'get_firmware_version' and not args.fw_id:
        print("X --fw-id is required for get_firmware_version test")
        sys.exit(1)

    kwargs = {}
    if args.task_id:
        kwargs['task_id'] = args.task_id
    if args.fw_image:
        kwargs['fw_image'] = args.fw_image
    if args.target:
        kwargs['target'] = args.target
    if args.eeprom_id:
        kwargs['eeprom_id'] = args.eeprom_id
    if args.fw_id:
        kwargs['fw_id'] = args.fw_id

    run_api_test(bmc, args.test, **kwargs) 
