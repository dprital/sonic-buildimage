import os
import pytest
import sys
import subprocess
import json

if sys.version_info.major == 3:
    from unittest import mock
else:
    import mock

test_path = os.path.dirname(os.path.abspath(__file__))
modules_path = os.path.dirname(test_path)
sys.path.insert(0, modules_path)

from sonic_platform.redfish_client import RedfishClient


def mock_logger():
    mock_obj = mock.Mock()
    mock_obj.log_error = mock.Mock()
    mock_obj.log_warning = mock.Mock()
    mock_obj.log_notice = mock.Mock()
    mock_obj.log_info = mock.Mock()
    mock_obj.log_debug = mock.Mock()
    return mock_obj

logger = mock_logger()

def load_redfish_response(fname):
    if not fname:
        return b''
    fpath = os.path.join(test_path, fname)
    file = open(fpath, 'r')
    content = file.read()
    file.close()
    return bytes(f'{content}', 'utf-8')


class TestRedfishClient:
    CURL_PATH = '/usr/bin/curl'
    BMC_INTERNAL_IP_ADDR = '169.254.0.1'
    BMC_NOS_ACCOUNT = 'yormnAnb'
    BMC_NOS_ACCOUNT_DEFAULT_PASSWORD = "ABYX12#14artb51"

    def password_callback(self):
        return TestRedfishClient.BMC_NOS_ACCOUNT_DEFAULT_PASSWORD

    @mock.patch('subprocess.Popen')
    def test_login_sucess(self, mock_popen):
        side_effects = []
        for fname in ['mock_bmc_login_token_response', \
            'mock_bmc_logout_response']:
            output = (load_redfish_response(fname), b'')
            mock_process = mock.Mock()
            mock_process.communicate.return_value = output
            mock_process.returncode = 0
            side_effects.append(mock_process)

        # Configure the side_effect to return different mock processes
        mock_popen.side_effect = side_effects
        rf = RedfishClient(TestRedfishClient.CURL_PATH,
                           TestRedfishClient.BMC_INTERNAL_IP_ADDR,
                           TestRedfishClient.BMC_NOS_ACCOUNT,
                           self.password_callback,
                           logger)

        ret = rf.login()
        assert ret == RedfishClient.ERR_CODE_OK
        assert rf.get_login_token() is not None

        ret = rf.logout()
        assert ret == RedfishClient.ERR_CODE_OK
        assert rf.get_login_token() is None

    @mock.patch('subprocess.Popen')
    def test_login_failure_bad_credential(self, mock_popen):
        output = (load_redfish_response('mock_bmc_empty_response_auth_failure'), b'')
        mock_popen.return_value.communicate.return_value = output
        mock_popen.return_value.returncode = 0
        rf = RedfishClient(TestRedfishClient.CURL_PATH,
                           TestRedfishClient.BMC_INTERNAL_IP_ADDR,
                           TestRedfishClient.BMC_NOS_ACCOUNT,
                           self.password_callback,
                           logger)

        ret = rf.login()
        assert ret == RedfishClient.ERR_CODE_AUTH_FAILURE
        assert rf.get_login_token() is None
    
    @mock.patch('subprocess.Popen')
    def test_get_bmc_version(self, mock_popen):
        side_effects = []
        for fname in ['mock_bmc_login_token_response', \
            'mock_get_bmc_info_response']:
            output = (load_redfish_response(fname), b'')
            mock_process = mock.Mock()
            mock_process.communicate.return_value = output
            mock_process.returncode = 0
            side_effects.append(mock_process)

        # Configure the side_effect to return different mock processes
        mock_popen.side_effect = side_effects
        rf = RedfishClient(TestRedfishClient.CURL_PATH,
                           TestRedfishClient.BMC_INTERNAL_IP_ADDR,
                           TestRedfishClient.BMC_NOS_ACCOUNT,
                           self.password_callback,
                           logger)

        ret = rf.login()
        assert ret == RedfishClient.ERR_CODE_OK
        assert rf.get_login_token() is not None

        ret, version = rf.redfish_api_get_firmware_version('MGX_FW_BMC_0')
        assert ret == RedfishClient.ERR_CODE_OK
        assert version == 'V.88.0002.0500-04'
    
    @mock.patch('subprocess.Popen')
    def test_change_bmc_login_password_root_user_success(self, mock_popen):
        side_effects = []
        for fname in ['mock_bmc_login_token_response', \
            'mock_change_bmc_login_password_success_response', \
            'mock_bmc_logout_response', \
            'mock_bmc_login_token_response']:
            output = (load_redfish_response(fname), b'')
            mock_process = mock.Mock()
            mock_process.communicate.return_value = output
            mock_process.returncode = 0
            side_effects.append(mock_process)

        # Configure the side_effect to return different mock processes
        mock_popen.side_effect = side_effects
        rf = RedfishClient(TestRedfishClient.CURL_PATH,
                           TestRedfishClient.BMC_INTERNAL_IP_ADDR,
                           TestRedfishClient.BMC_NOS_ACCOUNT,
                           self.password_callback,
                           logger)

        ret = rf.login()
        assert ret == RedfishClient.ERR_CODE_OK
        assert rf.get_login_token() is not None

        ret, err_msg = rf.redfish_api_change_login_password('0penBmcTempPass!', 'root')
        assert ret == RedfishClient.ERR_CODE_OK
    
    @mock.patch('subprocess.Popen')
    def test_trigger_bmc_debug_log_dump_success(self, mock_popen):
        side_effects = []
        for fname in ['mock_bmc_login_token_response', \
            'mock_bmc_debug_log_dump_response']:
            output = (load_redfish_response(fname), b'')
            mock_process = mock.Mock()
            mock_process.communicate.return_value = output
            mock_process.returncode = 0
            side_effects.append(mock_process)

        # Configure the side_effect to return different mock processes
        mock_popen.side_effect = side_effects
        rf = RedfishClient(TestRedfishClient.CURL_PATH,
                           TestRedfishClient.BMC_INTERNAL_IP_ADDR,
                           TestRedfishClient.BMC_NOS_ACCOUNT,
                           self.password_callback,
                           logger)

        ret = rf.login()
        assert ret == RedfishClient.ERR_CODE_OK
        assert rf.get_login_token() is not None

        ret, _ = rf.redfish_api_trigger_bmc_debug_log_dump()
        assert ret == RedfishClient.ERR_CODE_OK

    @mock.patch('subprocess.Popen')
    def test_get_bmc_debug_log_dump_success(self, mock_popen):
        side_effects = []
        for fname in ['mock_bmc_login_token_response', \
            'mock_bmc_task_query_valid_debug_log_dump',
            'mock_bmc_empty_response']:
            output = (load_redfish_response(fname), b'')
            mock_process = mock.Mock()
            mock_process.communicate.return_value = output
            mock_process.returncode = 0
            side_effects.append(mock_process)

        # Configure the side_effect to return different mock processes
        mock_popen.side_effect = side_effects
        rf = RedfishClient(TestRedfishClient.CURL_PATH,
                           TestRedfishClient.BMC_INTERNAL_IP_ADDR,
                           TestRedfishClient.BMC_NOS_ACCOUNT,
                           self.password_callback,
                           logger)

        ret = rf.login()
        assert ret == RedfishClient.ERR_CODE_OK
        assert rf.get_login_token() is not None

        ret, msg = rf.redfish_api_get_bmc_debug_log_dump(task_id='0', filename='test.tar.xz', file_path='/tmp')
        assert ret == RedfishClient.ERR_CODE_OK
    
    @mock.patch('subprocess.Popen')
    def test_get_bmc_eeprom(self, mock_popen):
        side_effects = []
        for fname in ['mock_bmc_login_token_response', \
            'mock_get_bmc_eeprom_response']:
            output = (load_redfish_response(fname), b'')
            mock_process = mock.Mock()
            mock_process.communicate.return_value = output
            mock_process.returncode = 0
            side_effects.append(mock_process)

        # Configure the side_effect to return different mock processes
        mock_popen.side_effect = side_effects
        rf = RedfishClient(TestRedfishClient.CURL_PATH,
                           TestRedfishClient.BMC_INTERNAL_IP_ADDR,
                           TestRedfishClient.BMC_NOS_ACCOUNT,
                           self.password_callback,
                           logger)

        ret = rf.login()
        assert ret == RedfishClient.ERR_CODE_OK
        assert rf.get_login_token() is not None

        ret, eeprom_content = rf.redfish_api_get_eeprom_info('BMC_eeprom')
        eeprom_dict_file_path = os.path.join(test_path, 'mock_parsed_bmc_eeprom_dict')
        with open(eeprom_dict_file_path, 'r') as f:
            data = f.read()
            expected_bmc_eeprom_dict_output = json.loads(data)

        assert ret == RedfishClient.ERR_CODE_OK
        assert expected_bmc_eeprom_dict_output == eeprom_content
