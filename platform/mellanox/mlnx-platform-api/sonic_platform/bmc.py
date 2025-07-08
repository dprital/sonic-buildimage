#
# SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
# Copyright (c) 2022-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
#############################################################################
# Mellanox
#
# Module contains an implementation of new platform api
#
#############################################################################


try:
    from functools import wraps
    import os
    import re
    import subprocess
    import json
    from sonic_platform_base.bmc_base import BMCBase
    from sonic_py_common import device_info
    from sonic_py_common.logger import Logger
    from .redfish_client import RedfishClient
    from . import utils
    import functools
    import filelock
except ImportError as e:
    raise ImportError (str(e) + "- required module not found")

logger = Logger()


def under_lock(lockfile, timeout=2):
    """ Execute operations under lock. """

    def _under_lock(func):
        @functools.wraps(func)
        def wrapped_function(*args, **kwargs):
            with filelock.FileLock(lockfile, timeout):
                return func(*args, **kwargs)

        return wrapped_function
    return _under_lock


def with_credential_restore(api_func):
    @wraps(api_func)
    def wrapper(self, *args, **kwargs):
        if self.rf_client is None:
            raise Exception('Redfish instance initialization failure')

        if not self.rf_client.has_login():
            # No need to check login result here since we can't decide the
            # correct type of return value of 'api_func()' for now.
            # 'api_func()' will be executed regardless. If login fails,
            # 'api_func()' will return code ERR_CODE_NOT_LOGIN, and the correct
            # type of additional data.
            self.login()
        elif api_func.__name__ in ['update_firmware_on_component', 'update_firmware']:
            # W/A for the case when we need to install new FW (takes quite long
            # time). While this process, current token can be expired, so the code
            # to pool task status will fail. To prevent it - invalidate token and
            # create the new before running API to do FW update.
            self.logout()
            self.login()

        ret, data = api_func(self, *args, **kwargs)
        if ret == RedfishClient.ERR_CODE_AUTH_FAILURE:
            # Trigger credential restore flow
            logger.log_notice(f'{api_func.__name__}() returns bad credential. ' \
                              'Trigger BMC TPM based password recovery flow')
            restored = self._restore_tpm_credential()
            if restored:
                # Execute again
                logger.log_notice(f'BMC TPM based password recovered. Retry {api_func.__name__}()')
                ret, data = api_func(self, *args, **kwargs)
            else:
                logger.log_notice(f'Fail to recover BMC based password')
                return (RedfishClient.ERR_CODE_AUTH_FAILURE, data)
        return (ret, data)
    return wrapper


class BMC(BMCBase):

    '''
    BMC encapsulates BMC device details such as IP address, credential management.
    It also acts as wrapper of RedfishClient.
    '''

    CURL_PATH = '/usr/bin/curl'
    BMC_ADMIN_ACCOUNT = 'admin'
    BMC_ADMIN_ACCOUNT_DEFAULT_PASSWORD = '0penBmc'
    BMC_NOS_ACCOUNT = 'yormnAnb'
    BMC_NOS_ACCOUNT_DEFAULT_PASSWORD = "ABYX12#14artb51"
    BMC_DIR = "/host/bmc"
    MAX_LOGIN_ERROR_PROBE_CNT = 5
    # TODO(BMC): change nvos to sonic
    BMC_TPM_HEX_FILE = "nvos_const.bin"

    _instance = None

    def __init__(self, addr):

        self.addr = addr
        # Use the NOS account by default. If login fails with the NOS account
        # then try with the admin account
        self.using_nos_account = True
        # Login password will be default password while doing TPM password
        # recovery. This flag is used for Redfishclient callback to decide
        # which password to use in login()
        self.using_tpm_password = True
        self.probe_cnt = 0

        self.rf_client = RedfishClient(BMC.CURL_PATH,
                                        addr,
                                        self.get_login_user,
                                        self.get_password_callback,
                                        logger)

    @staticmethod
    def get_instance():
        bmc_data = device_info.get_bmc_data()
        if not bmc_data:
            return None

        if BMC._instance is None:
            BMC._instance = BMC(bmc_data['bmc_addr'])

        return BMC._instance
    
    # TODO(BMC): Implement the DeviceBase interface methods

    def get_ip_addr(self):
        return self.addr

    def get_login_user(self):
        if self.using_nos_account:
            return BMC.BMC_NOS_ACCOUNT
        return BMC.BMC_ADMIN_ACCOUNT

    # Password callback function passed to RedfishClient.
    # It is not desired to store password in RedfishClient
    # instance for security concern.
    def get_password_callback(self):
        if self.using_tpm_password:
            return self.get_login_password()
        else:
            if self.using_nos_account:
                return BMC.BMC_NOS_ACCOUNT_DEFAULT_PASSWORD
            return BMC.BMC_ADMIN_ACCOUNT_DEFAULT_PASSWORD

    @under_lock(lockfile=f'{BMC_DIR}/{BMC_TPM_HEX_FILE}.lock', timeout=5)
    def get_login_password(self):
        try:
            pass_len = 13
            attempt = 1
            max_attempts = 100
            max_repeat = int(3 + 0.09 * pass_len)
            # TODO(BMC): change nvos to sonic
            hex_data = "1300NVOS-BMC-USER-Const"
            os.makedirs(self.BMC_DIR, exist_ok=True)
            cmd = f'echo "{hex_data}" | xxd -r -p >  {self.BMC_DIR}/{self.BMC_TPM_HEX_FILE}'
            subprocess.run(cmd, shell=True, check=True)

            tpm_command = ["tpm2_createprimary", "-C", "o", "-u",  f"{self.BMC_DIR}/{self.BMC_TPM_HEX_FILE}", "-G", "aes256cfb"]
            result = subprocess.run(tpm_command, capture_output=True, check=True, text=True)

            while attempt <= max_attempts:
                if attempt > 1:
                    # TODO(BMC): change nvos to sonic
                    const = f"1300NVOS-BMC-USER-Const-{attempt}"
                    mess = f"Password did not meet criteria; retrying with const: {const}"
                    logger.log_debug(mess)
                    tpm_command = f'echo -n "{const}" | tpm2_createprimary -C o -G aes -u -'
                    result = subprocess.run(tpm_command, shell=True, capture_output=True, check=True, text=True)

                symcipher_pattern = r"symcipher:\s+([\da-fA-F]+)"
                symcipher_match = re.search(symcipher_pattern, result.stdout)

                if not symcipher_match:
                    raise Exception("Symmetric cipher not found in TPM output")

                # BMC dictates a password of 13 characters. Random from TPM is used with an append of A!
                symcipher_part = symcipher_match.group(1)[:pass_len-2]
                if symcipher_part.isdigit():
                    symcipher_value = symcipher_part[:pass_len-3] + 'vA!'
                elif symcipher_part.isalpha() and symcipher_part.islower():
                    symcipher_value = symcipher_part[:pass_len-3] + '9A!'
                else:
                    symcipher_value = symcipher_part + 'A!'
                if len (symcipher_value) != pass_len:
                    raise Exception("Bad cipher length from TPM output")
                
                # check for monotonic
                monotonic_check = True
                for i in range(len(symcipher_value) - 3): 
                    seq = symcipher_value[i:i+4] 
                    increments = [ord(seq[j+1]) - ord(seq[j]) for j in range(3)]
                    if increments == [1, 1, 1] or increments == [-1, -1, -1]:
                        monotonic_check = False
                        break

                variety_check = len(set(symcipher_value)) >= 5
                repeating_pattern_check = sum(1 for i in range(pass_len - 1) if symcipher_value[i] == symcipher_value[i + 1]) <= max_repeat

                # check for consecutive_pairs
                count = 0
                for i in range(11):
                    val1 = symcipher_value[i]
                    val2 = symcipher_value[i + 1]
                    if val2 == "v" or val1 == "v":
                        continue
                    if abs(int(val2, 16) - int(val1, 16)) == 1:
                        count += 1
                consecutive_pair_check = count <= 4

                if consecutive_pair_check and variety_check and repeating_pattern_check and monotonic_check:
                    os.remove(f"{self.BMC_DIR}/{self.BMC_TPM_HEX_FILE}")
                    return symcipher_value
                else:
                    attempt += 1

            raise Exception("Failed to generate a valid password after maximum retries.")

        except subprocess.CalledProcessError as e:
            logger.log_error(f"Error executing TPM command: {e}")
            raise Exception("Failed to communicate with TPM")

        except Exception as e:
            logger.log_error(f"Error: {e}")
            raise

    def _restore_tpm_credential(self):

        logger.log_notice(f'Start BMC TPM password recovery flow')

        # We are not good with TPM based password here.
        # Try to login with default password.
        logger.log_notice(f'Try to login with BMC default password')
        # Indicate password callback function to switch to BMC_ADMIN_ACCOUNT_DEFAULT_PASSWORD temporarily
        self.using_tpm_password = False
        ret = self.rf_client.login()

        if ret != RedfishClient.ERR_CODE_OK:
            logger.log_error(f'Bad credential: Fail to login BMC with both TPM based and default passwords')
            if self.probe_cnt < BMC.MAX_LOGIN_ERROR_PROBE_CNT:
                # Need to log the exact failure reason since the /login REST API
                # does not return anything.
                # Trigger a GET request using user/password instead of token, then
                # BMC will report the failure details.
                self.rf_client.probe_login_error()
                self.probe_cnt += 1
            # Resume to TPM password
            self.using_tpm_password = True
            return False

        # Indicate RedfishClient to switch to TPM password
        self.using_tpm_password = True

        logger.log_notice(f'Login successfully with BMC default password')
        try:
            password = self.get_login_password()
        except Exception as e:
            self.rf_client.invalidate_login_token()
            logger.log_error(f'Fail to get login password from TPM: {str(e)}')
            return False

        logger.log_notice(f'Try to apply TPM based password to BMC')
        ret, msg = self.change_login_password(password)
        if ret != RedfishClient.ERR_CODE_OK:
            self.rf_client.invalidate_login_token()
            logger.log_error(f'Fail to apply TPM based password to BMC')
            return False

        logger.log_notice(f'BMC password is restored successfully')

        # TPM based password has been restored.
        return True

    def get_login_token(self):
        if self.rf_client is None:
            return None

        return self.rf_client.get_login_token()

    def get_component_list(self):

        # TBD: As the future improvement, the logic of loading all components
        #  (including non-BMC managed entities) can be implemented in a
        # component manager from which BMC can retrieve relevant components.
        # Each component is configured with its attributes and class in
        # platform_components.json. Thus we can load the components in a
        # generic manner.

        platform_path = device_info.get_path_to_platform_dir()
        platform_components_json_path = \
            os.path.join(platform_path, 'platform_components.json')
        comp_data = utils.load_json_file(platform_components_json_path)

        if not comp_data or len(comp_data.get('chassis', {})) == 0:
            return []

        if 'component' not in comp_data['chassis']:
            return []

        components =  comp_data['chassis']['component']
        comp_list = []

        for comp_name, attrs in components.items():
            # Skip if not managed by BMC
            managed_by = attrs.get('managed_by', '')
            if managed_by.upper() != 'BMC':
                continue

            comp_cls = attrs.get('class', '')
            if len(comp_cls) == 0:
                logger.log_error(f"Missing 'class' for component {comp_name} in platform_components.json")
                continue

            comp = None
            from . import component as module
            try:
                cls = getattr(module, comp_cls)
                if cls is None:
                    logger.log_error(f"Bad value 'class {comp_cls}' for component {comp_name} in platform_components.json")
                    continue

                comp = cls(comp_name, attrs)
            except:
                continue
            comp_list.append(comp)

        # The reason why comp_list is not cached in BMC is the concern of circular
        # reference with ComponentBMCObj. Anyway, future improvement will move
        # component list management part to Chassis. Chassis holds component list
        # references.

        return comp_list

    def get_component_by_name(self, name):
        comp_list = list(filter(lambda comp: comp.name == name, self.get_component_list()))
        return comp_list[0] if len(comp_list) > 0 else None

    def get_component_by_fw_id(self, fw_id):
        comp_list = list(filter(lambda comp: comp.fw_id == fw_id, self.get_component_list()))
        return comp_list[0] if len(comp_list) > 0 else None

    def get_component_list_by_type(self, type_name):
        comp_list = list(filter(lambda comp: comp.type_name == type_name, self.get_component_list()))
        return comp_list

    def try_login(self):
        account = 'NOS' if self.using_nos_account else 'admin'
        logger.log_notice(f'Try login to BMC using the {account} account')

        if self.rf_client is None:
            return RedfishClient.ERR_CODE_AUTH_FAILURE

        ret = self.rf_client.login()

        if ret == RedfishClient.ERR_CODE_AUTH_FAILURE:
            logger.log_notice(f'Fail to login BMC with TPM password. Trigger password recovery flow')
            restored = self._restore_tpm_credential()
            if restored:
                ret = RedfishClient.ERR_CODE_OK
        elif ret == RedfishClient.ERR_CODE_PASSWORD_UNAVAILABLE:
            logger.log_notice(f'Fail to generate TPM password')

        return ret

    def login(self):
        self.using_nos_account = True
        ret = self.try_login()
        if ret != RedfishClient.ERR_CODE_OK:
            self.using_nos_account = False
            ret = self.try_login()
        return ret

    def logout(self):
        if self.rf_client and self.rf_client.has_login():
            return self.rf_client.logout()
        else:
            return RedfishClient.ERR_CODE_OK

    def change_login_password(self, password, user=None):
        if self.rf_client is None:
            return (RedfishClient.ERR_CODE_AUTH_FAILURE, "")

        return self.rf_client.redfish_api_change_login_password(password, user)

    # TODO(BMC): Check if should call it in files/scripts/load_system_info
    def check_and_reset_tpm_password_for_user(self, user: str = BMC_ADMIN_ACCOUNT) -> bool:
        '''
        Check if the provided user has tpm password and if not,
        generate a new tpm password and apply it to the user.

        Returns True if the TPM password is restored for the user or
                user was already with TPM password, False otherwise.
        '''
        self.using_nos_account = True if user == self.BMC_NOS_ACCOUNT else False

        if self.rf_client is None:
            return False

        # By default, BMC password callback will use TPM password
        (ret, response) = self.rf_client.probe_login_error()
        if ret == RedfishClient.ERR_CODE_AUTH_FAILURE:
            logger.log_notice(f'User {user} does not have TPM password, restore it')
            if self._restore_tpm_credential():
                logger.log_notice(f'TPM password restored for user {user}')
                return True
            else:
                logger.log_error(f'Fail to restore TPM password for user {user}')
                return False
        elif ret != RedfishClient.ERR_CODE_OK:
            logger.log_error(f'Fail to check TPM password for user {user}: {response}')
            return False

        return True

    @with_credential_restore
    def get_firmware_list(self):
        return self.rf_client.redfish_api_get_firmware_list()

    @with_credential_restore
    def get_firmware_version(self, fw_id):
        return self.rf_client.redfish_api_get_firmware_version(fw_id)

    @with_credential_restore
    def get_eeprom_info(self, eeprom_id):
        return self.rf_client.redfish_api_get_eeprom_info(eeprom_id)

    @with_credential_restore
    def get_eeprom_list(self):
        return self.rf_client.redfish_api_get_eeprom_list()

    @with_credential_restore
    def update_firmware(self, fw_image, timeout = 1800, progress_callback = None):
        logger.log_notice(f'Installing firmware image {fw_image} via BMC')
        ret, msg = self.rf_client.redfish_api_update_firmware(fw_image, timeout, progress_callback)
        logger.log_notice(f'Firmware update result: {ret}')
        if ret:
            logger.log_notice(f'{msg}')

        return (ret, msg)

    @with_credential_restore
    def update_firmware_on_component(self, fw_image, fw_ids, timeout = 1800, progress_callback = None):
        # Set component ID to be updated
        logger.log_notice(f'Set BMC update targets: {fw_ids}')
        ret, msg = self.rf_client.redfish_api_set_component_update(fw_ids)
        if ret != RedfishClient.ERR_CODE_OK:
            return (ret, 'Fail to set Component ID attribute')

        logger.log_notice(f'Installing firmware image {fw_image} via BMC')
        ret, msg = self.rf_client.redfish_api_update_firmware(fw_image, timeout, progress_callback)
        logger.log_notice(f'Firmware update result: {ret}')
        if ret:
            logger.log_notice(f'{msg}')

        # Reset component ID from to be updated
        logger.log_notice(f'Clear BMC update targets')
        _, _ = self.rf_client.redfish_api_set_component_update(None)

        return (ret, msg)

    @with_credential_restore
    def trigger_bmc_debug_log_dump(self):
        return self.rf_client.redfish_api_trigger_bmc_debug_log_dump()

    @with_credential_restore
    def get_bmc_debug_log_dump(self, task_id, filename, path):
        return self.rf_client.redfish_api_get_bmc_debug_log_dump(task_id, filename, path)
    
    # TODO(BMC): Verify which functions are needed for BMC

    # @with_credential_restore
    # def get_erot_copy_background_status(self, erot_component_id):
    #     return self.rf_client.redfish_api_get_erot_copy_background_status(erot_component_id)

    # @with_credential_restore
    # def get_erots_debug_token_status(self):
    #     return self.rf_client.redfish_api_get_debug_token_status()

    # @with_credential_restore
    # def get_erot_active_and_inactive_flashes(self, erot_id):
    #     return self.rf_client.redfish_api_get_erot_active_and_inactive_flashes(erot_id)

    # @with_credential_restore
    # def get_erot_ap_boot_status(self, erot_id):
    #     return self.rf_client.redfish_api_get_erot_ap_boot_status(erot_id)
