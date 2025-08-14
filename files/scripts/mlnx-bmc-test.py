#!/usr/bin/env python3


import sonic_platform
import sys
import os
import argparse
import time
import tqdm
from sonic_py_common.logger import Logger


logger = Logger()
logger.set_min_log_priority_info()


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


def test_get_bmc_eeprom(bmc):
    """Test get BMC EEPROM API"""
    print("\n=== Testing Get BMC EEPROM ===")
    
    try:
        eeprom_info = bmc.get_eeprom()
        print(f"V BMC EEPROM retrieved successfully")
        print(f"EEPROM info: {eeprom_info}")
        return True
    except Exception as e:
        print(f"X Failed to get BMC EEPROM: {e}")
        return False


def test_get_bmc_version(bmc):
    """Test get BMC version API"""
    print("\n=== Testing Get BMC Version ===")
    
    try:
        version = bmc.get_version()
        print(f"V BMC version: {version}")
        return True
    except Exception as e:
        print(f"X Failed to get BMC version: {e}")
        return False


def test_change_password(bmc):
    """Test change password API"""
    print("\n=== Testing Change Password ===")
    
    try:
        print("Testing password change for root user...")
        ret = bmc.login()
        if ret != 0:
            print("Failed to login to BMC")
            return False
        user = 'root'
        password = 'ABYX12#14artb'
        
        ret, msg = bmc.change_login_password(password, user)
        print(f"Change password result: {ret}")
        print(f"Message: {msg}")
        
        if ret == 0:
            print("V Root password change successful")
        else:
            print("X Root password change failed")
        
        return ret == 0
    except Exception as e:
        print(f"X Exception during password change: {e}")
        return False


def test_reset_password(bmc):
    """Test reset password API"""
    print("\n=== Testing Reset Password ===")
    
    try:
        print("Testing password reset...")
        ret, msg = bmc.reset_root_password()
        print(f"Reset password result: {ret}")
        print(f"Message: {msg}")
        
        if ret == 0:
            print("V BMC password reset successful")
        else:
            print("X BMC password reset failed")
        
        return ret == 0
    except Exception as e:
        print(f"X Exception during password reset: {e}")
        return False


def test_get_bmc_name(bmc):
    """Test get BMC name API"""
    print("\n=== Testing Get BMC Name ===")
    
    try:
        name = bmc.get_name()
        print(f"V BMC name: {name}")
        return True
    except Exception as e:
        print(f"X Failed to get BMC name: {e}")
        return False


def test_get_bmc_presence(bmc):
    """Test get BMC presence API"""
    print("\n=== Testing Get BMC Presence ===")
    
    try:
        presence = bmc.get_presence()
        print(f"V BMC presence: {presence}")
        return True
    except Exception as e:
        print(f"X Failed to get BMC presence: {e}")
        return False


def test_get_bmc_model(bmc):
    """Test get BMC model API"""
    print("\n=== Testing Get BMC Model ===")
    
    try:
        model = bmc.get_model()
        print(f"V BMC model: {model}")
        return True
    except Exception as e:
        print(f"X Failed to get BMC model: {e}")
        return False


def test_get_bmc_serial(bmc):
    """Test get BMC serial API"""
    print("\n=== Testing Get BMC Serial ===")
    
    try:
        serial = bmc.get_serial()
        print(f"V BMC serial: {serial}")
        return True
    except Exception as e:
        print(f"X Failed to get BMC serial: {e}")
        return False


def test_get_bmc_revision(bmc):
    """Test get BMC revision API"""
    print("\n=== Testing Get BMC Revision ===")
    
    try:
        revision = bmc.get_revision()
        print(f"V BMC revision: {revision}")
        return True
    except Exception as e:
        print(f"X Failed to get BMC revision: {e}")
        return False


def test_get_bmc_status(bmc):
    """Test get BMC status API"""
    print("\n=== Testing Get BMC Status ===")
    
    try:
        status = bmc.get_status()
        print(f"V BMC status: {status}")
        return True
    except Exception as e:
        print(f"X Failed to get BMC status: {e}")
        return False


def test_is_bmc_replaceable(bmc):
    """Test is BMC replaceable API"""
    print("\n=== Testing Is BMC Replaceable ===")
    
    try:
        replaceable = bmc.is_replaceable()
        print(f"V BMC replaceable: {replaceable}")
        return True
    except Exception as e:
        print(f"X Failed to check if BMC is replaceable: {e}")
        return False


def test_request_power_cycle(bmc, immediate=False):
    """Test BMC power cycle API"""
    print("\n=== Testing BMC Power Cycle ===")
    
    try:
        print(f"Requesting power cycle (immediate: {immediate})...")
        ret, err_msg = bmc.request_power_cycle(immediate)
        print(f"Power cycle result: {ret}")
        
        if ret == 0:
            print("V BMC power cycle request successful")
            if immediate:
                print("System will power cycle immediately")
            else:
                print("System will power cycle gracefully")
        else:
            print(f"X Failed to request BMC power cycle: {err_msg}")
        
        return ret == 0
    except Exception as e:
        print(f"X Exception during power cycle request: {e}")
        return False


def test_upgrade_bmc_firmware(bmc, fw_image, target=None, force_update=False, timeout=1800):
    """Test BMC firmware upgrade API"""
    print("\n=== Testing BMC Firmware Upgrade ===")
    
    if not os.path.exists(fw_image):
        print(f"X Firmware image file not found: {fw_image}")
        return False
    
    print(f'Flashing {fw_image} to BMC...')

    pbar = tqdm.tqdm(total=100)
    def create_progress_callback():
        last_percent = 0

        def callback(progress_data):
            nonlocal last_percent
            percent = progress_data['percent']
            delta = percent - last_percent
            last_percent = percent
            pbar.update(delta)

        return callback

    progress_callback = create_progress_callback()

    start = time.time()
    try:
        ret, msg = bmc.update_firmware(fw_image)
        pbar.close()
        print(f'Time elapsed: {int((time.time() - start) * 10) / 10}s')
        if ret == 0:
            print(f'V Firmware is successfully updated: {msg}')
            return True
        else:
            print(f'X Fail to update firmware {ret} {msg}')
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
        'get_name': test_get_bmc_name,
        'get_presence': test_get_bmc_presence,
        'get_model': test_get_bmc_model,
        'get_serial': test_get_bmc_serial,
        'get_revision': test_get_bmc_revision,
        'get_status': test_get_bmc_status,
        'is_replaceable': test_is_bmc_replaceable,
        'get_eeprom': test_get_bmc_eeprom,
        'get_version': test_get_bmc_version,
        'get_ip': test_get_bmc_ip_addr,
        'get_eeprom_list': test_get_bmc_eeprom_list,
        'get_firmware_list': test_get_bmc_firmware_list,
        'trigger_dump': test_trigger_bmc_debug_log_dump,
        'get_dump': lambda bmc: test_get_bmc_debug_log_dump(bmc, kwargs.get('task_id')),
        'change_password': test_change_password,
        'reset_password': test_reset_password,
        'upgrade_firmware': lambda bmc: test_upgrade_bmc_firmware(bmc, kwargs.get('fw_image')),
        'power_cycle': lambda bmc: test_request_power_cycle(bmc, kwargs.get('immediate', False)),
    }
    
    if api_name in api_tests:
        return api_tests[api_name](bmc)
    else:
        print(f"X Unknown API test: {api_name}")
        return False


if __name__ == '__main__':

    if os.geteuid() != 0:
        print('Please run under root privilege.')
        sys.exit(-1)

    parser = argparse.ArgumentParser(description='BMC API Test Tool - Run one test at a time')
    parser.add_argument("--test", choices=['get_name', 'get_presence', 'get_model', 'get_serial', 'get_revision', 'get_status',
                                           'is_replaceable', 'get_eeprom', 'get_version', 'get_ip', 'get_eeprom_list',
                                           'get_eeprom_info', 'get_firmware_list', 'get_firmware_version', 'trigger_dump',
                                           'get_dump', 'change_password', 'reset_password', 'upgrade_firmware', 'power_cycle'],
                        required=True, help="Test a specific BMC API")
    parser.add_argument("--task-id", help="Task ID for get_dump test")
    parser.add_argument("--fw-image", help="Firmware image file for upgrade_firmware test")
    parser.add_argument("--eeprom-id", help="EEPROM ID for get_eeprom_info test")
    parser.add_argument("--fw-id", help="Firmware ID for get_firmware_version test")
    parser.add_argument("--immediate", action="store_true", help="Immediate power cycle for power_cycle test")

    args = parser.parse_args()

    try:
        chassis = sonic_platform.platform.Platform().get_chassis()
        bmc = chassis.get_bmc()
        if bmc is None:
            print('X No BMC exists')
            sys.exit(0)
    except Exception as e:
        print('X BMC object is not ready')
        sys.exit(1)

    bmc_ip = bmc.get_ip_addr()
    print(f"BMC IP address: {bmc_ip}")

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
    if args.eeprom_id:
        kwargs['eeprom_id'] = args.eeprom_id
    if args.fw_id:
        kwargs['fw_id'] = args.fw_id
    if args.immediate:
        kwargs['immediate'] = args.immediate

    run_api_test(bmc, args.test, **kwargs)
    try:
        bmc.logout()
    except Exception as e:
        print(f"X Exception during BMC logout: {e}")
