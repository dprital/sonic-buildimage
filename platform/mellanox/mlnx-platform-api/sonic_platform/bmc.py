#
# SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
# Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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
    import time
except ImportError as e:
    raise ImportError (str(e) + "- required module not found")


logger = Logger()


def ping(host):
    # Construct the ping command
    # -c 1: Send only one packet
    # -W 1: Wait 1 second for a response
    command = ['/usr/bin/ping', '-c', '1', '-W', '1', host]

    try:
        subprocess.check_output(command, stderr=subprocess.STDOUT)
        return True
    except subprocess.CalledProcessError:
        return False


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
        elif api_func.__name__ == 'update_firmware':
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
    BMC_NOS_ACCOUNT = 'yormnAnb'
    BMC_NOS_ACCOUNT_DEFAULT_PASSWORD = "ABYX12#14artb51"
    BMC_DIR = "/host/bmc"
    MAX_LOGIN_ERROR_PROBE_CNT = 5
    # TODO(BMC): change nvos to sonic
    BMC_TPM_HEX_FILE = "nvos_const.bin"

    _instance = None

    def __init__(self, addr):

        self.addr = addr
        # Login password will be default password while doing TPM password
        # recovery. This flag is used for Redfishclient callback to decide
        # which password to use in login()
        self.using_tpm_password = True
        self.probe_cnt = 0

        self.rf_client = RedfishClient(BMC.CURL_PATH,
                                        addr,
                                        BMC.BMC_NOS_ACCOUNT,
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

    def get_ip_addr(self):
        return self.addr

    # Password callback function passed to RedfishClient.
    # It is not desired to store password in RedfishClient
    # instance for security concern.
    def get_password_callback(self):
        if self.using_tpm_password:
            return self.get_login_password()
        else:
            return BMC.BMC_NOS_ACCOUNT_DEFAULT_PASSWORD

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
        # Indicate password callback function to switch to default password temporarily
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

        # Apply TPM password to NOS account.
        logger.log_notice(f'Try to apply TPM based password to BMC NOS account')
        ret, msg = self.change_login_password(password)
        if ret != RedfishClient.ERR_CODE_OK:
            self.rf_client.invalidate_login_token()
            logger.log_error(f'Fail to apply TPM based password to BMC NOS account')
            return False
        else:
            logger.log_notice(f'TPM password is successfully applied to BMC NOS account')

        # Apply TPM password to legacy admin account.
        # These part of code will be removed once BMC removes the admin account.
        logger.log_notice(f'Try to apply TPM based password to BMC admin account')
        ret, msg = self.change_login_password(password, 'admin')
        if ret != RedfishClient.ERR_CODE_OK:
            logger.log_error(f'Fail to apply TPM based password to BMC admin account')
        else:
            logger.log_notice(f'TPM password is successfully applied to BMC admin account')

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

    def login(self):
        logger.log_notice(f'Try login to BMC using the NOS account')
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

    def logout(self):
        if self.rf_client and self.rf_client.has_login():
            return self.rf_client.logout()
        else:
            return RedfishClient.ERR_CODE_OK

    def change_login_password(self, password, user=None):
        if self.rf_client is None:
            return (RedfishClient.ERR_CODE_AUTH_FAILURE, "")

        return self.rf_client.redfish_api_change_login_password(password, user)
    
    def enable_log(self, enable=True):
        self.rf_client.enable_log(enable)

    # TODO(BMC): Check if should call it in files/scripts/load_system_info
    # check_and_reset_tpm_password_for_user(self, user: str = BMC_ADMIN_ACCOUNT) -> bool
    # bmc.change_login_password(bmc.get_login_password(), 'admin')

    # TODO(BMC): Implement APIs
    '''
    get_name()

    get_presence()

    get_model()

    get_serial()

    get_revision()

    get_status()

    is_replaceable()


    get_eeprom()

    get_version()

    # TODO(BMC): check if params are needed or use the root
    reset_password()

    collect_dump()

    update_firmware(fw_image)
    '''

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
    def request_power_cycle(self, immediate):
        return self.rf_client.redfish_api_request_system_reset(
            sytem_reset_type=RedfishClient.SYSTEM_RESET_TYPE_POWER_CYCLE, immediate=immediate)

    @with_credential_restore
    def request_power_cycle_bypass(self):
        ret, err_msg = self.rf_client.redfish_api_request_system_reset(
            sytem_reset_type=RedfishClient.SYSTEM_RESET_TYPE_POWER_CYCLE_BYPASS, immediate=False)

        # If power cycle bypass is not supported, try power cycle
        if ret == RedfishClient.ERR_CODE_UNSUPPORTED_PARAMETER:
            ret, err_msg = self.rf_client.redfish_api_request_system_reset(
                sytem_reset_type=RedfishClient.SYSTEM_RESET_TYPE_POWER_CYCLE, immediate=False)

        return (ret, err_msg)

    @with_credential_restore
    def request_cpu_reset(self):
        return self.rf_client.redfish_api_request_system_reset(
            sytem_reset_type=RedfishClient.SYSTEM_RESET_TYPE_CPU_RESET, immediate=True)

    @with_credential_restore
    def update_firmware(self, fw_image, fw_ids=None, force_update=False, progress_callback=None, timeout=1800):
        # First try to update without force
        logger.log_notice(f'Installing firmware image {fw_image} via BMC, force_update: {force_update}')
        result = self.rf_client.redfish_api_update_firmware(fw_image,
                                                            fw_ids,
                                                            force_update,
                                                            timeout,
                                                            progress_callback)
        ret, msg, updated_components, skipped_components = result

        logger.log_notice(f'Firmware update result: {ret}')
        if msg:
            logger.log_notice(f'{msg}')

        # TODO(BMC): Check if we need to force update also when force_update is False
        # Downgrade detected, try to do force update
        if (not force_update) and (ret == RedfishClient.ERR_CODE_LOWER_VERSION):
            # Exclude the components that have already been updated or skipped
            if fw_ids:
                fw_ids = [comp for comp in fw_ids if comp not in updated_components]
                fw_ids = [comp for comp in fw_ids if comp not in skipped_components]

            prev_updated_components = updated_components
            prev_msg = msg

            logger.log_notice(f'Firmware image timestamp is lower than the current timestamp')
            logger.log_notice(f'Attempting to force update')
            result = self.rf_client.redfish_api_update_firmware(fw_image,
                                                                fw_ids,
                                                                True,
                                                                timeout,
                                                                progress_callback)
            ret, msg, updated_components, skipped_components = result

            logger.log_notice(f'Firmware update result: {ret}')
            if msg:
                logger.log_notice(f'{msg}')

            msg = prev_msg + msg
            updated_components = prev_updated_components + updated_components

        # Replace BMC internal firmware id with component display name in the message
        for comp in self.get_component_list():
            msg = msg.replace(comp.get_firmware_id(), comp.get_name())

        # Set updated flag to True if there are components updated
        updated = (len(updated_components) > 0)

        return (ret, (msg, updated))

    @with_credential_restore
    def trigger_bmc_debug_log_dump(self):
        return self.rf_client.redfish_api_trigger_bmc_debug_log_dump()

    @with_credential_restore
    def get_bmc_debug_log_dump(self, task_id, filename, path):
        return self.rf_client.redfish_api_get_bmc_debug_log_dump(task_id, filename, path)
    
    def wait_until_reachable(self, timeout):
        start_time = time.time()

        while time.time() - start_time < timeout:
            if ping(self.addr):
                return True
            time.sleep(1)

        return False
    
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
