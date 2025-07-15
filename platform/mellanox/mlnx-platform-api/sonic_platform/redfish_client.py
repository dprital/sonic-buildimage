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
# Module contains an implementation of RedFish client which provides
# firmware upgrade and sensor retrieval functionality
#
#############################################################################


import subprocess
import json
import time
import re
import shlex
# TODO(BMC): Verify if pydash is needed according to the commented functions below
# import pydash as py_


'''
A stub logger class which prints log message to screen.
It can be used for debugging standalone file.
'''
class ConsoleLogger:
    def __getattr__(self, name):
        # Intercept calls to methods that start with 'log_'
        supported_methods = ['log_error',
                             'log_warning',
                             'log_notice',
                             'log_info',
                             'log_debug']
        if name in supported_methods:
            def method(*args, **kwargs):
                print(*args, **kwargs)
            return method

        # Raise an AttributeError for other methods
        err_msg = f"'{self.__class__.__name__}' object has no attribute '{name}'"
        raise AttributeError(err_msg)


def is_auth_failure(http_status_code):
    return (http_status_code == '401')


'''
cURL wrapper for Redfish client access
'''
class RedfishClient:

    DEFAULT_TIMEOUT = 3
    DEFAULT_LOGIN_TIMEOUT = 4

    # Redfish URIs
    REDFISH_URI_FW_INVENTORY = '/redfish/v1/UpdateService/FirmwareInventory'
    REDFISH_URI_CHASSIS_INVENTORY = '/redfish/v1/Chassis'
    REDFISH_URI_TASKS = '/redfish/v1/TaskService/Tasks'
    REDFISH_URI_UPDATE_SERVICE = '/redfish/v1/UpdateService'
    REDFISH_URI_ACCOUNTS = '/redfish/v1/AccountService/Accounts'
    REDFISH_DEBUG_TOKEN = '/redfish/v1/Systems/System_0/LogServices/DebugTokenService'
    REDFISH_BMC_LOG_DUMP = '/redfish/v1/Managers/BMC_0/LogServices/Dump/Actions'

    REDFISH_URI_CHASSIS = '/redfish/v1/Chassis'

    # Error code definitions
    ERR_CODE_OK = 0
    ERR_CODE_AUTH_FAILURE = -1
    ERR_CODE_INVALID_JSON_FORMAT = -2
    ERR_CODE_UNEXPECTED_RESPONSE = -3
    ERR_CODE_CURL_FAILURE = -4
    ERR_CODE_NOT_LOGIN = -5
    ERR_CODE_TIMEOUT = -6
    ERR_CODE_IDENTICAL_IMAGE = -7
    ERR_CODE_PASSWORD_UNAVAILABLE = -8
    ERR_CODE_URI_NOT_FOUND = -9
    ERR_CODE_SERVER_UNREACHABLE = -10
    ERR_CODE_GENERIC_ERROR = -11

    CURL_ERR_OK = 0
    CURL_ERR_OPERATION_TIMEDOUT = 28
    CURL_ERR_COULDNT_RESOLVE_HOST = 6
    CURL_ERR_FAILED_CONNECT_TO_HOST = 7
    CURL_ERR_SSL_CONNECT_ERROR = 35

    CURL_TO_REDFISH_ERROR_MAP = \
    {
        CURL_ERR_COULDNT_RESOLVE_HOST :   ERR_CODE_SERVER_UNREACHABLE,
        CURL_ERR_FAILED_CONNECT_TO_HOST : ERR_CODE_SERVER_UNREACHABLE,
        CURL_ERR_SSL_CONNECT_ERROR :      ERR_CODE_SERVER_UNREACHABLE,
        CURL_ERR_OPERATION_TIMEDOUT :     ERR_CODE_TIMEOUT,
        CURL_ERR_OK :                     ERR_CODE_OK
    }

    '''
    Constructor
    A password_callback parameter is provoided because:
    1. Password is not allowed to be saved for security concern.
    2. If token expires or becomes invalid for some reason (for example, being
    revoked from BMC web interface), RedfishClient will do login retry in which
    password is required anyway. It will get password from an external password
    provider, for example class BMC which holds the responsibility of generating
    password from TPM.
    '''
    def __init__(self, curl_path, ip_addr, user_callback, password_callback, logger = None):
        self.__curl_path = curl_path
        self.__svr_ip = ip_addr
        self.__user_callback = user_callback
        self.__password_callback = password_callback
        self.__token = None
        self.__default_timeout = RedfishClient.DEFAULT_TIMEOUT
        self.__default_login_timeout = RedfishClient.DEFAULT_LOGIN_TIMEOUT
        if logger is None:
            self.__logger = ConsoleLogger()
        else:
            self.__logger = logger

        self.__logger.log_notice(f'RedfishClient instance is created\n')

    def get_login_token(self):
        return self.__token

    def curl_errors_to_redfish_erros_translation(self, curl_error):
        return self.CURL_TO_REDFISH_ERROR_MAP.get(
                    curl_error, RedfishClient.ERR_CODE_CURL_FAILURE)

    def invalidate_login_token(self):
        self.__logger.log_notice(f'Invalidate login token')
        self.__token = None

    '''
    Build the POST command to login and get bearer token
    '''
    def __build_login_cmd(self, password):
        user = self.__user_callback()
        cmd = f'{self.__curl_path} -m {self.__default_login_timeout} -k ' \
              f'-H "Content-Type: application/json" ' \
              f'-X POST https://{self.__svr_ip}/login ' \
              f'-d \'{{"username" : "{user}", "password" : "{password}"}}\''
        return cmd

    '''
    Build the POST command to logout and release the token
    '''
    def __build_logout_cmd(self):
        cmd = f'{self.__curl_path} -k -H "X-Auth-Token: {self.__token}" ' \
              f'-X POST https://{self.__svr_ip}/logout'

        return cmd

    '''
    Build the GET command
    '''
    def __build_get_cmd(self, uri, output_file = None):
        output_str = '' if not output_file else f'--output {output_file}'
        cmd = f'{self.__curl_path} -m {self.__default_timeout} -k ' \
              f'-H "X-Auth-Token: {self.__token}" --request GET ' \
              f'--location https://{self.__svr_ip}{uri} ' \
              f'{output_str}'
        return cmd

    '''
    Build a GET command using user/password to probe login account error
    '''
    def __build_login_probe_cmd(self):
        uri = RedfishClient.REDFISH_URI_ACCOUNTS
        user = self.__user_callback()
        password = self.__password_callback()
        cmd = f'{self.__curl_path} -m {self.__default_timeout} -k ' \
              f'-u {user}:{password} --request GET ' \
              f'--location https://{self.__svr_ip}{uri} '
        return cmd

    '''
    Build the POST command to do firmware upgdate
    '''
    def __build_fw_update_cmd(self, fw_image):
        cmd = f'{self.__curl_path} -k -H "X-Auth-Token: {self.__token}" ' \
              f'-H "Content-Type: application/octet-stream" -X POST ' \
              f'https://{self.__svr_ip}' \
              f'{RedfishClient.REDFISH_URI_UPDATE_SERVICE} -T {fw_image}'
        return cmd

    '''
    Build the PATCH command to change login password
    '''
    def __build_change_password_cmd(self, new_password, user):
        if user is None:
            user = self.__user_callback()

        cmd = f'{self.__curl_path} -k -H "X-Auth-Token: {self.__token}" ' \
              f'-H "Content-Type: application/json" -X PATCH ' \
              f'https://{self.__svr_ip}' \
              f'{RedfishClient.REDFISH_URI_ACCOUNTS}/{user} ' \
              f'-d \'{{"Password" : "{new_password}"}}\''
        return cmd

    '''
    Build the PATCH command to set component attribute to update FW
    '''
    def __build_set_component_update_cmd(self, comps):
        comps_uris = [f'"{RedfishClient.REDFISH_URI_FW_INVENTORY}/{comp}"' for comp in comps]
        comps_uris_str = ', '.join(comps_uris)
        cmd = f'{self.__curl_path} -k -H "X-Auth-Token: {self.__token}" ' \
              f'-X PATCH -d \'{{"HttpPushUriTargets":['\
              f'{comps_uris_str}'\
              f']}}\' ' \
              f'https://{self.__svr_ip}' \
              f'{RedfishClient.REDFISH_URI_UPDATE_SERVICE}'
        return cmd

    '''
    Build the PATCH command to reset component attribute to update FW
    '''
    def __build_set_component_update_reset_cmd(self):
        cmd = f'{self.__curl_path} -k -H "X-Auth-Token: {self.__token}" ' \
              f'-X PATCH -d \'{{"HttpPushUriTargets":[]}}\' ' \
              f'https://{self.__svr_ip}' \
              f'{RedfishClient.REDFISH_URI_UPDATE_SERVICE}'
        return cmd

    # TODO(BMC): Verify if this function is needed according to the commented functions below
    # '''
    # Build the POST command to start debug toke request
    # '''
    # def __build_debug_token_cmd(self, debug_token_status=False):
    #     data_type = "DebugTokenStatus" if debug_token_status else "GetDebugTokenRequest"
    #     cmd = f'{self.__curl_path} -k -H "X-Auth-Token: {self.__token}" ' \
    #           f'-H "Content-Type: application/json" ' \
    #           f'-X POST https://{self.__svr_ip}' \
    #           f'{RedfishClient.REDFISH_DEBUG_TOKEN}/LogService.CollectDiagnosticData ' \
    #           f'-d \'{{"DiagnosticDataType":"OEM", "OEMDiagnosticDataType":"{data_type}"}}\''
    #     return cmd

    '''
    Build the POST command to start BMC debug dump request Redfish Task
    '''
    def __build_bmc_debug_log_dump_cmd(self):
        cmd = f'{self.__curl_path} -k -H "X-Auth-Token: {self.__token}" ' \
              f'-H "Content-Type: application/json" ' \
              f'-X POST https://{self.__svr_ip}' \
              f'{RedfishClient.REDFISH_BMC_LOG_DUMP}/LogService.CollectDiagnosticData ' \
              '-d \'{"DiagnosticDataType":"Manager"}\''
        return cmd

    '''
    Obfuscate username and password while asking for bearer token
    '''
    def __obfuscate_user_password(self, cmd):
        # Obfuscate 'username' and 'password' in the payload
        # For example: login
        pattern = r'"username" : "[^"]*", "password" : "[^"]*"'
        replacement = '"username" : "******", "password" : "******"'
        obfuscation_cmd = re.sub(pattern, replacement, cmd)

        # Obfuscate username and password in the command line parameter
        # For example: use user:password directly in the command to do
        # login failure probe
        pattern =  r'-u [!-~]+:[!-~]+'
        replacement = '-u ******:******'
        obfuscation_cmd = re.sub(pattern, replacement, obfuscation_cmd)

        return obfuscation_cmd

    '''
    Obfuscate bearer token in the response string
    '''
    def __obfuscate_token_response(self, response):
        # Credential obfuscation
        pattern = r'"token": "[^"]*"'
        replacement = '"token": "******"'
        obfuscation_response = re.sub(pattern,
                                        replacement,
                                        response)
        return obfuscation_response

    '''
    Obfuscate bearer token passed to cURL
    '''
    def __obfuscate_auth_token(self, cmd):
        pattern = r'X-Auth-Token: [^"]+'
        replacement = 'X-Auth-Token: ******'

        obfuscation_cmd = re.sub(pattern, replacement, cmd)
        return obfuscation_cmd

    '''
    Obfuscate password while aksing for password change
    '''
    def __obfuscate_password(self, cmd):
        pattern = r'"Password" : "[^"]*"'
        replacement = '"Password" : "******"'
        obfuscation_cmd = re.sub(pattern, replacement, cmd)

        return obfuscation_cmd

    '''
    Parse cURL output to extract response and HTTP status code
    Return value:
        Tuple of JSON response and HTTP status code
    '''
    def __parse_curl_output(self, curl_output):
        response_str = None
        http_status_code = '000'

        pattern = r'([\s\S]*?)\nHTTP Status Code: (\d+)$'
        match = re.search(pattern, curl_output, re.MULTILINE)

        if match:
            response_str = match.group(1)     # The JSON part
            http_status_code = match.group(2) # The HTTP status code
        else:
            # Unlikely to happen. Bug of cURL
            self.__logger.log_error(f'Unexpected curl output: {curl_output}\n')

        # response_str 'None' means format error
        return (response_str, http_status_code)

    '''
    Execute cURL command and return the output and error messages
    Return value:
        ERR_CODE_OK
        ERR_CODE_TIMEOUT
        ERR_CODE_CURL_FAILURE
    '''
    def __exec_curl_cmd_internal(self, cmd):
        # Will not print task monitor to syslog
        task_mon = (RedfishClient.REDFISH_URI_TASKS in cmd)
        login_cmd = ('/login ' in cmd)
        password_change = (RedfishClient.REDFISH_URI_ACCOUNTS in cmd)
        print_to_syslog = not isinstance(self.__logger, ConsoleLogger)

        # Credential obfuscation
        obfuscation_cmd = self.__obfuscate_user_password(cmd)
        obfuscation_cmd = self.__obfuscate_auth_token(obfuscation_cmd)

        if password_change:
            obfuscation_cmd = self.__obfuscate_password(obfuscation_cmd)

        # For syslog, skip logs for task monitor requests
        # since there are too many
        if print_to_syslog:
            if not task_mon:
                self.__logger.log_debug(obfuscation_cmd + '\n')
        else:
            self.__logger.log_debug(cmd + '\n')

        # Instruct curl to append HTTP status code after JSON response
        cmd += ' -w "\nHTTP Status Code: %{http_code}"'
        process = subprocess.Popen(shlex.split(cmd),
                                   stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE)
        output, error = process.communicate()
        output_str, http_status_code = self.__parse_curl_output(output.decode('utf-8'))
        error_str = error.decode('utf-8')
        ret = process.returncode

        if http_status_code != '200':
            self.__logger.log_notice(f'HTTP status code {http_status_code}, output {output_str}, error {error_str}')

        # No HTTP status code found
        if http_status_code is None:
            ret = RedfishClient.ERR_CODE_CURL_FAILURE
            error_str = 'Unexpected curl output'
            return (ret, http_status_code, output_str, error_str, obfuscation_cmd)

        if (ret == RedfishClient.CURL_ERR_OK): # cURL retuns ok
            ret = RedfishClient.ERR_CODE_OK

            if login_cmd:
                obfuscation_output_str = \
                    self.__obfuscate_token_response(output_str)
            else:
                obfuscation_output_str = output_str

            # For syslog, skip logs for task monitor responses
            # except the last one since there are too many
            if print_to_syslog:
                if not task_mon:
                    msg = f'Output:\n{obfuscation_output_str}\n'
                    self.__logger.log_debug(msg)
                else:
                    complete_str = '"PercentComplete": 100'
                    task_complete = (complete_str in obfuscation_output_str)
                    if task_complete:
                        self.__logger.log_notice(obfuscation_cmd + '\n')
                        msg = f'Output:\n{obfuscation_output_str}\n'
                        self.__logger.log_notice(msg)
            else:
                msg = f'Output:\n{output_str}\n'
                self.__logger.log_debug(msg)
        else: # cURL returns error
            cmd_to_log = obfuscation_cmd if print_to_syslog else cmd
            self.__logger.log_notice(f'curl error on executing command: {cmd_to_log}')
            self.__logger.log_notice(f'Error: {error_str}')

            ret = self.curl_errors_to_redfish_erros_translation(ret)

        return (ret, http_status_code, output_str, error_str, obfuscation_cmd)

    '''
    Extract URI from the job response

    Example of Payload:
        "Payload": {
            "HttpHeaders": [
            "Host: 10.0.1.1",
            "User-Agent: curl/7.74.0",
            "Accept: */*",
            "Content-Length: 76",
            "Location: /redfish/v1/Systems/System_0/LogServices/DebugTokenService/Entries/0/attachment"
            ],
            "HttpOperation": "POST",
            "JsonBody": "{\n  \"DiagnosticDataType\": \"OEM\",\n  \"OEMDiagnosticDataType\": \"GetDebugTokenRequest\"\n}",
            "TargetUri": "/redfish/v1/Systems/System_0/LogServices/DebugTokenService/LogService.CollectDiagnosticData"
        }
    '''
    def __get_uri_from_response(self, response):
        try:
            json_response = json.loads(response)
        except Exception as e:
            msg = 'Error: Invalid JSON format'
            return (RedfishClient.ERR_CODE_INVALID_JSON_FORMAT, msg, None)

        if "Payload" not in json_response:
            ret = RedfishClient.ERR_CODE_UNEXPECTED_RESPONSE
            err_msg = "Error: Missing 'Payload' field"
            return (ret, err_msg, None)

        payload = json_response["Payload"]
        if "HttpHeaders" not in payload:
            ret = RedfishClient.ERR_CODE_UNEXPECTED_RESPONSE
            err_msg = "Error: Missing 'HttpHeaders' field"
            return (ret, err_msg, None)

        http_headers = payload["HttpHeaders"]
        uri = None
        for header in http_headers:
            if "Location" in header:
                uri = header.split()[-1]

        if not uri:
            ret = RedfishClient.ERR_CODE_UNEXPECTED_RESPONSE
            err_msg = "Error: Missing 'Location' field"
            return (ret, err_msg, None)

        return (RedfishClient.ERR_CODE_OK, "", uri)

    '''
    Log json response
    '''
    def __log_json_response(self, response):
        lines = response.splitlines()
        for line in lines:
            self.__logger.log_notice(line)

    '''
    Replace old token in the command.
    This happens in case token becomes invalid and re-login is triggered.
    '''
    def __update_token_in_command(self, cmd):
        pattern = r'X-Auth-Token:\s*[^\s\"\']+'
        new_cmd = re.sub(pattern, 'X-Auth-Token: ' + self.__token, cmd)

        return new_cmd

    '''
    Wrapper function to execute the given cURL command which can deal with
    invalid bearer token case.
    Return value:
        ERR_CODE_OK
        ERR_CODE_NOT_LOGIN
        ERR_CODE_TIMEOUT
        ERR_CODE_CURL_FAILURE
        ERR_CODE_AUTH_FAILURE
    '''
    def exec_curl_cmd(self, cmd, max_retries=2):
        is_login_cmd = ('/login ' in cmd)

        # Not login, return
        if (not self.has_login()) and (not is_login_cmd):
            self.__logger.log_error('Need to login first before executing curl command\n')
            return (RedfishClient.ERR_CODE_NOT_LOGIN, 'Not login', 'Not login')

        ret, http_status_code, output_str, error_str, obfuscation_cmd \
            = self.__exec_curl_cmd_internal(cmd)

        # cURL execution timeout, try again
        i = 0
        while (i < max_retries) and (ret == RedfishClient.ERR_CODE_TIMEOUT):

            # TBD:
            # Add rechability test (interface down/no ip) here.
            # If unreachable, no need to retry. Set unreachable flat at meanwhile.
            # If this flag is set, exectute_curl_cmd() needs to do reachablity test
            # before executing curl command. Then it avoids getting stuck in curl
            # until timeout. The flag will be reset once we have a successful curl
            # command executed.

            # Increase timeout temporarily
            timeout = None
            match = re.search(r'-m\s*(\d+)', cmd)
            if match:
                timeout = int(match.group(1))
                timeout += 2
                cmd = re.sub(r'-m\s*\d+', f'-m {timeout}', cmd)

            msg = f"exec '{cmd}' (retry_number={i}" + f" timeout={timeout}s)" if timeout else ")"
            self.__logger.log_debug(msg + '\n')

            ret, http_status_code, output_str, error_str, obfuscation_cmd \
                = self.__exec_curl_cmd_internal(cmd)

            i += 1

        # Authentication failure might happen in case of:
        #   - Incorrect password
        #   - Invalid token (Token may become invalid for some reason.
        #     For example, remote side may clear the session table or change password.
        #   - Account locked
        if not is_auth_failure(http_status_code):
            return (ret, output_str, error_str)

        # Authentication failure on login, report error.
        if is_login_cmd:
            return (RedfishClient.ERR_CODE_AUTH_FAILURE, 'Authentication failure', 'Authentication failed')

        # Authentication failure for other commands.
        # We can't differentiate various scenarios that may cause authentication failure.
        # Just do a re-login and retry the command and expect to recover.
        self.__logger.log_notice(f"Got HTTP status code '401' response: {obfuscation_cmd}\n")
        self.__logger.log_notice(f'Re-login and retry last command...\n')
        self.invalidate_login_token()
        ret = self.login()
        if ret == RedfishClient.ERR_CODE_OK:
            self.__logger.log_notice(f'Login successfully. Rerun last command\n')
            cmd = self.__update_token_in_command(cmd)
            ret, http_status_code, output_str, error_str, _ = self.__exec_curl_cmd_internal(cmd)
            if ret != RedfishClient.ERR_CODE_OK:
                self.__logger.log_notice(f'Command rerun returns error {ret}\n')
            elif is_auth_failure(http_status_code):
                self.__logger.log_notice(f'Command rerun fails as authentication failure\n')
                self.invalidate_login_token()
                ret = RedfishClient.ERR_CODE_AUTH_FAILURE
                output_str = error_str = 'Authentication failure'
            return (ret, output_str, error_str)
        elif ret == RedfishClient.ERR_CODE_AUTH_FAILURE:
            # Login fails, invalidate token.
            self.__logger.log_notice(f'Failed to login. Return as authentication failure\n')
            self.invalidate_login_token()
            return (ret, 'Authentication failure', 'Authentication failure')
        else:
            # Login fails, invalidate token.
            self.__logger.log_notice(f'Failed to login, error : {ret}\n')
            self.invalidate_login_token()
            return (ret, 'Login failure', 'Login failure')

    '''
    Check if already login
    '''
    def has_login(self):
        return self.__token is not None

    '''
    Login Redfish server and get bearer token
    '''
    def login(self):
        if self.has_login():
            return RedfishClient.ERR_CODE_OK

        try:
            password = self.__password_callback()
        except Exception as e:
            self.__logger.log_error(f'{str(e)}')
            return RedfishClient.ERR_CODE_PASSWORD_UNAVAILABLE

        cmd = self.__build_login_cmd(password)
        ret, response, error = self.exec_curl_cmd(cmd)

        if (ret != 0):
            msg = f'Login failure: code {ret}, {error}\n'
            self.__logger.log_error(msg)
            return ret

        if len(response) == 0:
            msg = 'Got empty Redfish login response.\n'
            self.__logger.log_error(msg)
            ret = RedfishClient.ERR_CODE_UNEXPECTED_RESPONSE
            return ret

        try:
            json_response = json.loads(response)
            if 'error' in json_response:
                msg = json_response['error']['message']
                self.__logger.log_error(f'{msg}\n')
                ret = RedfishClient.ERR_CODE_GENERIC_ERROR
            elif 'token' in json_response:
                token = json_response['token']
                if token is not None:
                    ret = RedfishClient.ERR_CODE_OK
                    self.__token = token
                    self.__logger.log_notice('Redfish login successfully and session token updated')
                else:
                    msg = 'Login failure: empty "token" field found\n'
                    self.__logger.log_error(msg)
                    ret = RedfishClient.ERR_CODE_UNEXPECTED_RESPONSE
            else:
                msg = 'Login failure: no "token" field found\n'
                self.__logger.log_error(msg)
                ret = RedfishClient.ERR_CODE_UNEXPECTED_RESPONSE
        except Exception as e:
            msg = 'Login failure: invalid json format\n'
            self.__logger.log_error(msg)
            self.__logger.log_json_response(response)
            ret = RedfishClient.ERR_CODE_INVALID_JSON_FORMAT

        return ret

    '''
    Logout Redfish server
    '''
    def logout(self):
        if not self.has_login():
            return RedfishClient.ERR_CODE_OK

        self.__logger.log_notice(f'Logout redfish session\n')

        cmd = self.__build_logout_cmd()
        ret, response, error = self.exec_curl_cmd(cmd)

        # Invalidate token anyway
        self.__token = None

        if (ret != 0): # cURL execution error
            msg = 'Logout failure: curl command returns error\n'
            self.__logger.log_notice(msg)
            return ret

        if len(response) == 0: # Invalid token
            msg = 'Got empty Redfish logout response. It indicates an invalid token\n'
            self.__logger.log_notice(msg)
            return ret

        try:
            json_response = json.loads(response)

            if 'status' in json_response:
                status = json_response['status']
                if status != 'ok':
                    self.__logger.log_notice(f'Redfish response for logout failure: \n')
                    self.__log_json_response(response)
        except Exception as e:
            msg = 'Logout failure: invalid json format\n'
            self.__logger.log_error(msg)
            ret = RedfishClient.ERR_CODE_INVALID_JSON_FORMAT

        return ret

    '''
    Use GET command with user/password to probe the exact error reason in case
    of login failure
    '''
    def probe_login_error(self):
        cmd = self.__build_login_probe_cmd()
        ret, _, response, error, _ = self.__exec_curl_cmd_internal(cmd)

        if (ret != 0): # cURL execution error,
            msg = 'Probe login failure: curl command returns error\n'
            self.__logger.log_notice(msg)
            return (RedfishClient.ERR_CODE_GENERIC_ERROR, response)

        if len(response) == 0:
            msg = 'Got empty response.\n'
            self.__logger.log_notice(msg)
            return (RedfishClient.ERR_CODE_UNEXPECTED_RESPONSE, msg)

        try:
            json_response = json.loads(response)
        except Exception as e:
            msg = 'Probe login failure: invalid json format\n'
            self.__logger.log_error(msg)
            return (RedfishClient.ERR_CODE_INVALID_JSON_FORMAT, msg)

        if 'error' in json_response: # Error found
            # Log just in case of error response
            self.__logger.log_notice(f'Redfish response for login failure probe: \n')
            self.__log_json_response(response)

            err = json_response['error']
            if 'code' in err:
                err_code = err['code']
                if 'ResourceAtUriUnauthorized' in err_code:
                    ret = RedfishClient.ERR_CODE_AUTH_FAILURE
                    err_msg = "Account is locked or wrong password"
                else:
                    ret = RedfishClient.ERR_CODE_UNEXPECTED_RESPONSE
                    err_msg = f"Not expected error code: {err_code}"
            else:
                ret = RedfishClient.ERR_CODE_UNEXPECTED_RESPONSE
                err_msg = "Missing 'error code' field"

            return (ret, f'Error: {err_msg}')

        return (RedfishClient.ERR_CODE_OK, response)


    '''
    Get firmware inventory

    Parameters:   None
    Return value:  (ret, firmware_list)
      ret               return code
      firmware_list     list of tuple (fw_id, version)
    '''
    def redfish_api_get_firmware_list(self):
        cmd = self.__build_get_cmd(RedfishClient.REDFISH_URI_FW_INVENTORY)
        ret, response, error = self.exec_curl_cmd(cmd)

        if (ret != RedfishClient.ERR_CODE_OK):
            return (ret, [])

        try:
            json_response = json.loads(response)
            item_list = json_response["Members"]
        except json.JSONDecodeError as e:
            return (RedfishClient.ERR_CODE_INVALID_JSON_FORMAT, [])
        except Exception as e:
            return (RedfishClient.ERR_CODE_UNEXPECTED_RESPONSE, [])

        fw_list = []
        for item in item_list:
            fw_id = item["@odata.id"].split('/')[-1]

            ret, version = self.redfish_api_get_firmware_version(fw_id)
            if (ret != RedfishClient.ERR_CODE_OK):
                version = "N/A"

            fw_list.append((fw_id, version))

        return (RedfishClient.ERR_CODE_OK, fw_list)


    '''
    Get firmware version by given ID

    Parameters:
      fw_id       firmware ID
    Return value:  (ret, version)
      ret         return code
      version     firmware version string
    '''
    def redfish_api_get_firmware_version(self, fw_id):
        version = 'N/A'

        uri = f'{RedfishClient.REDFISH_URI_FW_INVENTORY}/{fw_id}'
        cmd = self.__build_get_cmd(uri)
        ret, response, error_msg = self.exec_curl_cmd(cmd)

        if (ret == RedfishClient.ERR_CODE_OK):
            try:
                json_response = json.loads(response)
                if 'Version' in json_response:
                    version = json_response['Version']
                else:
                    msg = 'Error: Version not found in Redfish response\n'
                    self.__logger.log_error(msg)
                    self.__log_json_response(response)
            except json.JSONDecodeError as e:
                msg = f'Error: Invalid Redfish response JSON format on querying {fw_id} version\n'
                self.__logger.log_notice(msg)
                self.__log_json_response(response)
                ret = RedfishClient.ERR_CODE_INVALID_JSON_FORMAT
            except Exception as e:
                msg = f'Error: Exception {str(e)} caught on querying {fw_id} version\n'
                self.__logger.log_notice(msg)
                self.__log_json_response(response)
                ret = RedfishClient.ERR_CODE_UNEXPECTED_RESPONSE
        else:
            msg = f'Got error {ret} on querying {fw_id} version: {error_msg}\n'
            self.__logger.log_notice(msg)

        return (ret, version)


    '''
    Update firmware

    Parameters:
      fw_image    firmware image path
      timeout     timeout value in seconds
    Return value:  (ret, error_msg)
      ret         return code
      error_msg   error message string
    '''
    def redfish_api_update_firmware(self, fw_image, timeout = 1800, progress_callback = None):
        # Trigger FW upgrade
        cmd = self.__build_fw_update_cmd(fw_image)
        ret, response, error_msg = self.exec_curl_cmd(cmd)
        if (ret != RedfishClient.ERR_CODE_OK):
            return (ret, f'Error: {error_msg}')

        try:
            json_response = json.loads(response)
        except Exception as e:
            msg = 'Error: Invalid JSON format'
            return (RedfishClient.ERR_CODE_INVALID_JSON_FORMAT, msg)

        # Retrieve task id from response
        task_id = ''
        if 'error' in json_response: # Error found
            err = json_response['error']
            if 'message' in err:
                err_msg = err['message']
                ret = RedfishClient.ERR_CODE_GENERIC_ERROR
            else:
                ret = RedfishClient.ERR_CODE_UNEXPECTED_RESPONSE
                err_msg = "Missing 'message' field"
            return (ret, f'Error: {err_msg}')
        elif 'TaskStatus' in json_response:
            status = json_response['TaskStatus']
            if status == 'OK':
                task_id = json_response['Id']
            else:
                ret = RedfishClient.ERR_CODE_GENERIC_ERROR
                return (ret, f'Error: Return status is {status}')

        # Wait for completion
        ret, error_msg, _ = self.__wait_task_completion(task_id, timeout, progress_callback)

        return (ret, error_msg)


    '''
    Common function for both debug token info and debug token status APIs.
    It receives the response, parse it, wait for completion and extract
    URI with the path to result and return it.
    Parameters:
        response - JSON response from request command
        timeout - in seconds, how long to wait for task completion
    Return (ret_code, ret_msg or URI)
        ret_code - returned error code
        ret_msg - returned error message
        URI - path to take the results after task execution
    '''
    def _get_debug_token_responce(self, response, timeout):
        try:
            json_response = json.loads(response)
        except Exception as e:
            return (RedfishClient.ERR_CODE_INVALID_JSON_FORMAT, 'Error: Invalid JSON format')

        # Retrieve task id from response
        task_id = ''
        if 'error' in json_response: # Error found
            err = json_response['error']
            if 'message' in err:
                err_msg = err['message']
                ret = RedfishClient.ERR_CODE_GENERIC_ERROR
            else:
                ret = RedfishClient.ERR_CODE_UNEXPECTED_RESPONSE
                err_msg = "Missing 'message' field"
            return (ret, f'Error: {err_msg}')
        elif 'TaskStatus' in json_response:
            status = json_response['TaskStatus']
            if status == 'OK':
                task_id = json_response['Id']
            else:
                ret = RedfishClient.ERR_CODE_GENERIC_ERROR
                return (ret, f'Error: Return status is {status}')

        # Wait for completion
        ret, error_msg, response = self.__wait_task_completion(task_id, timeout, sleep_timeout=1)

        if ret != RedfishClient.ERR_CODE_OK:
            return (ret, error_msg)

        # Fetch the file with results
        ret, error_msg, uri = self.__get_uri_from_response(response)
        if ret != RedfishClient.ERR_CODE_OK or (not uri):
            return (ret, error_msg)

        return (RedfishClient.ERR_CODE_OK, uri)
    

    # TODO(BMC): Verify which functions are needed for BMC
    # '''
    # Get EROT copy-background-status

    # Parameters:
    #   erot_fw_id       erot component ID
    # Return value:  (ret, data)
    #   ret   return code
    #   data  EROT background-copy-status or error message
    # '''
    # def redfish_api_get_erot_copy_background_status(self, erot_fw_id: str) -> tuple():
    #     background_copy_status = 'N/A'
    #     # Make sure ERoT name doesn't have '_FW' part
    #     erot_id = re.sub('_FW', '', erot_fw_id)

    #     uri = f'{RedfishClient.REDFISH_URI_CHASSIS_INVENTORY}/{erot_id}'
    #     cmd = self.__build_get_cmd(uri)
    #     ret, response, error = self.exec_curl_cmd(cmd)

    #     if (ret == RedfishClient.ERR_CODE_OK):
    #         try:
    #             json_response = json.loads(response)
    #             background_copy_status = py_.get(json_response, 'Oem.Nvidia.BackgroundCopyStatus', default='N/A')
    #         except json.JSONDecodeError as e:
    #             return (RedfishClient.ERR_CODE_INVALID_JSON_FORMAT, 'Error: Invalid JSON format')
    #         except Exception as e:
    #             return (RedfishClient.ERR_CODE_UNEXPECTED_RESPONSE, 'Error: unexpected response')
    #     else:
    #         self.__logger.log_notice(f"Was not able to read copy-background-status on {erot_fw_id}, return code is {ret}, response {response}")

    #     return (ret, background_copy_status)


    # '''

    # Get debug token status

    # Parameters:
    #   timeout     timeout value in seconds
    # Return value:  (ret, (response, error_msg))
    #   ret         return code
    #   response    dictionary with ERoT component and its installed value
    #     E.g.:
    #     {
    #         "ERoT_CPU_0": {
    #             "TokenInstalled": false
    #         },
    #            . . .
    #         "ERoT_BMC_0": {
    #             "TokenInstalled": false
    #         }
    #     }

    #   error_msg   error message string
    # '''
    # def redfish_api_get_debug_token_status(self, timeout = 10):

    #     cmd = self.__build_debug_token_cmd(debug_token_status=True)
    #     ret, response, error_msg = self.exec_curl_cmd(cmd)
    #     if (ret != RedfishClient.ERR_CODE_OK):
    #         return (ret, f'Error: {error_msg}')

    #     ret, result = self._get_debug_token_responce(response, timeout)
    #     if ret != RedfishClient.ERR_CODE_OK:
    #         return (ret, f'Error: {result}')

    #     cmd = self.__build_get_cmd(result)
    #     ret, response, error_msg = self.exec_curl_cmd(cmd)

    #     try:
    #         json_response = json.loads(response)
    #     except json.JSONDecodeError as e:
    #         msg = 'Error: Invalid JSON format'
    #         return (RedfishClient.ERR_CODE_INVALID_JSON_FORMAT, msg)
    #     except Exception as e:
    #         msg = 'Error: unexpected response'
    #         return (RedfishClient.ERR_CODE_UNEXPECTED_RESPONSE, msg)

    #     result = {}
    #     erots_dict = json_response.get('DebugTokenStatus', [])
    #     for erot_dict in erots_dict:
    #         erot_id = erot_dict.get('@odata.id', '').replace('/redfish/v1/Chassis/', '')
    #         result[erot_id] = {'TokenInstalled': str(erot_dict.get('TokenInstalled', 'N/A'))}

    #     return (ret, result)


    # '''
    # Get EROT active & inactive flashes

    # Parameters:
    #   erot_fw_id      erot-id

    # Return value:  (ret, erot_info)
    #   ret         return code
    #   erot_info   erot_info containing active & inactive flashes
    # '''
    # def redfish_api_get_erot_active_and_inactive_flashes(self, erot_fw_id: str) -> tuple():
    #     active_flash = 'N/A'
    #     inactive_flash = 'N/A'

    #     uri = f'{RedfishClient.REDFISH_URI_FW_INVENTORY}/{erot_fw_id}'
    #     cmd = self.__build_get_cmd(uri)
    #     ret, response, error = self.exec_curl_cmd(cmd)

    #     if (ret == RedfishClient.ERR_CODE_OK):
    #         try:
    #             json_response = json.loads(response)
    #             active_flash = py_.get(json_response, 'Oem.Nvidia.ActiveFirmwareSlot.SlotId', default='N/A')
    #             inactive_flash = py_.get(json_response, 'Oem.Nvidia.InactiveFirmwareSlot.SlotId', default='N/A')
    #         except json.JSONDecodeError as e:
    #             return (RedfishClient.ERR_CODE_INVALID_JSON_FORMAT, 'Error: Invalid JSON format')
    #         except Exception as e:
    #             return (RedfishClient.ERR_CODE_UNEXPECTED_RESPONSE, 'Error: unexpected response')
    #     else:
    #         self.__logger.log_notice(f"Was not able to read active/inactive on {erot_fw_id}, return code is {ret}, response {response}")

    #     return (ret, {'active-flash': active_flash, 'inactive-flash': inactive_flash})


    # '''
    # Get EROT AP boot status

    # Parameters:
    #   erot_id      erot-id (for example MGX_FW_ERoT_CPU_0)

    # Return value:  (ret_code, ret_data)
    #   ret_code   return code
    #   ret_data   ret_data contains boot status (can be extended in the future)
    #              or error mesasge in case of return code is not 0
    # '''
    # def redfish_api_get_erot_ap_boot_status(self, erot_fw_id: str) -> tuple():
    #     boot_status = 'N/A'
    #     # Make sure ERoT name doesn't have '_FW' part
    #     erot_id = re.sub('_FW', '', erot_fw_id)
    #     # The resouce name is expected to be without 'ERoT' part
    #     resource_name = re.sub('_ERoT', '', erot_id)

    #     uri = f'{RedfishClient.REDFISH_URI_CHASSIS_INVENTORY}/{erot_id}/Oem/NvidiaRoT/RoTProtectedComponents/{resource_name}'
    #     cmd = self.__build_get_cmd(uri)
    #     ret, response, error = self.exec_curl_cmd(cmd)

    #     if (ret == RedfishClient.ERR_CODE_OK):
    #         try:
    #             json_response = json.loads(response)
    #             boot_status = json_response.get('BootStatusCode', 'N/A')
    #         except json.JSONDecodeError as e:
    #             return (RedfishClient.ERR_CODE_INVALID_JSON_FORMAT, 'Error: Invalid JSON format')
    #         except Exception as e:
    #             return (RedfishClient.ERR_CODE_UNEXPECTED_RESPONSE, 'Error: unexpected response')
    #     else:
    #         self.__logger.log_notice(f"Was not able to read AP boot status on {erot_fw_id}, return code is {ret}, response {response}")

    #     return (ret, {'boot-status': boot_status})


    '''

    Trigger BMC debug log dump file

    Return value:  (ret, (task_id, error_msg))
      ret         return code
      task_id     Redfish task-id to monitor
      error_msg   error message string
    '''
    def redfish_api_trigger_bmc_debug_log_dump(self):
        task_id = '-1'

        # Trigger debug log dump service
        cmd = self.__build_bmc_debug_log_dump_cmd()
        ret, response, error_msg = self.exec_curl_cmd(cmd)
        if (ret != RedfishClient.ERR_CODE_OK):
            return (ret, (task_id, f'Error: {error_msg}'))

        try:
            json_response = json.loads(response)
        except Exception as e:
            msg = 'Error: Invalid JSON format'
            return (RedfishClient.ERR_CODE_INVALID_JSON_FORMAT, (task_id, msg))

        # Retrieve task id from response
        if 'error' in json_response: # Error found
            err = json_response['error']
            if 'message' in err:
                err_msg = err['message']
                ret = RedfishClient.ERR_CODE_GENERIC_ERROR
            else:
                ret = RedfishClient.ERR_CODE_UNEXPECTED_RESPONSE
                err_msg = "Missing 'message' field"
            return (ret, (task_id, f'Error: {err_msg}'))
        elif 'TaskStatus' in json_response:
            status = json_response['TaskStatus']
            if status == 'OK':
                task_id = json_response.get('Id', '')
                ret = RedfishClient.ERR_CODE_OK
                return (ret, (task_id, None))
            else:
                ret = RedfishClient.ERR_CODE_GENERIC_ERROR
                return (ret, (task_id, f'Error: Return status is {status}'))


    '''
    Get BMC debug log dump file

    Parameters:
      filename    new file name
      file_path   location of the new file
      timeout     timeout value in seconds
    Return value:  (ret, error_msg)
      ret         return code
      error_msg   error message string
    '''
    def redfish_api_get_bmc_debug_log_dump(self, task_id, filename, file_path, timeout = 120):
        # Wait for completion
        ret, error_msg, response = self.__wait_task_completion(task_id, timeout)

        if ret != RedfishClient.ERR_CODE_OK:
            return (ret, error_msg)

        # Fetch the file
        ret, error_msg, uri = self.__get_uri_from_response(response)
        if ret != RedfishClient.ERR_CODE_OK:
            return (ret, error_msg)

        if not uri:
            ret = RedfishClient.ERR_CODE_GENERIC_ERROR
            return (ret, error_msg)

        output_file = f'{file_path}/{filename}'
        uri += '/attachment'
        cmd = self.__build_get_cmd(uri, output_file=output_file)
        ret, response, error_msg = self.exec_curl_cmd(cmd)

        return (ret, error_msg)


    '''
    Reads all the eeproms of the bmc

    Parameters:   None
    Return value:  (ret, eeprom_list)
      ret               return code
      eeprom_list     list of tuple (component_name, eeprom_data)
      eeprom_data     return value from redfish_api_get_eeprom_info called with component_name
    '''
    def redfish_api_get_eeprom_list(self):
        cmd = self.__build_get_cmd(RedfishClient.REDFISH_URI_CHASSIS_INVENTORY)
        ret, response, error = self.exec_curl_cmd(cmd)

        if (ret != RedfishClient.ERR_CODE_OK):
            return (ret, [])

        try:
            json_response = json.loads(response)
            item_list = json_response["Members"]
        except json.JSONDecodeError as e:
            return (RedfishClient.ERR_CODE_INVALID_JSON_FORMAT, [])
        except Exception as e:
            return (RedfishClient.ERR_CODE_UNEXPECTED_RESPONSE, [])

        eeprom_list = []
        for item in item_list:
            component_url = item.get("@odata.id")
            if not component_url:
                continue
            component_name = component_url.split('/')[-1]
            if 'eeprom' not in component_name:
                # If the name of the component doesn't contain eeprom,
                # it is not an eeprom. Ignore it.
                # For now, the only valid eeprom we have is BMC_eeprom.
                # But we will probably have more in the future
                continue
            ret, eeprom_values = self.redfish_api_get_eeprom_info(component_name)
            # No need for checking ret.
            # If it is a bad value,
            # redfish_api_get_eeprom_info will return a dictionary which indicates the error

            eeprom_list.append((component_name, eeprom_values))

        return (RedfishClient.ERR_CODE_OK, eeprom_list)

    '''
    Get eeprom values for a given component

    Parameters:
      component_name       component name
    Return value:  (ret, eeprom_data)
      ret         return code
      eeprom_data     dictionary containing eeprom data
    '''
    def redfish_api_get_eeprom_info(self, component_name):
        uri = f'{RedfishClient.REDFISH_URI_CHASSIS_INVENTORY}/{component_name}'
        cmd = self.__build_get_cmd(uri)
        ret, response, err_msg = self.exec_curl_cmd(cmd)

        bad_eeprom_info = {'State': 'Fail'}
        if (ret != RedfishClient.ERR_CODE_OK):
            return (ret, bad_eeprom_info)

        try:
            json_response = json.loads(response)
        except json.JSONDecodeError as e:
            ret = RedfishClient.ERR_CODE_INVALID_JSON_FORMAT
            return (ret, bad_eeprom_info)
        except Exception as e:
            ret = RedfishClient.ERR_CODE_UNEXPECTED_RESPONSE
            return (ret, bad_eeprom_info)

        if 'error' in json_response: # Error found
            err = json_response['error']
            if ('code' in err) and ('ResourceNotFound' in err['code']):
                ret = RedfishClient.ERR_CODE_URI_NOT_FOUND
            else:
                ret = RedfishClient.ERR_CODE_GENERIC_ERROR
            self.__logger.log_error(f'Got redfish error response for {component_name} query: \n')
            self.__log_json_response(response)
            return (ret, bad_eeprom_info)

        eeprom_info = {}
        for key,value in json_response.items():
            # Remove information that is not the eeprom content itself.
            # But part of the redfish protocol
            if '@odata' in str(value) or '@odata' in str(key):
                continue
            # Don't add the status, we will parse it and add it later
            if key == 'Status':
                continue
            eeprom_info[str(key)] = str(value)

        # Add 'Status'. Even if it is not exactly part of the eeprom,
        # it was part of the response we got.
        # Can be very usefull also to see the value.

        status = json_response.get('Status',{})
        eeprom_info['State'] = status.get('State', 'Ok')
        eeprom_info['Health'] = status.get('Health', 'Ok')
        eeprom_info['HealthRollup'] = status.get('HealthRollup', 'Ok')

        return (RedfishClient.ERR_CODE_OK, eeprom_info)

    '''
    Wait for given task to complete
    '''
    def __wait_task_completion(self, task_id, timeout = 1800, progress_callback = None, sleep_timeout = 2):
        # Polling task status by given task id

        uri = f'{RedfishClient.REDFISH_URI_TASKS}/{task_id}'
        cmd = self.__build_get_cmd(uri)

        start_tm = time.time()

        while True:
            ret, response, err_msg = self.exec_curl_cmd(cmd)
            if (ret != RedfishClient.ERR_CODE_OK):
                return (ret, f"Error: {err_msg}", response)

            try:
                json_response = json.loads(response)
            except Exception as e:
                msg = 'Error: Invalid JSON format'
                return (RedfishClient.ERR_CODE_INVALID_JSON_FORMAT, msg, response)

            percent = None
            if 'PercentComplete' in json_response:
                percent = json_response['PercentComplete']
                if progress_callback:
                    progress_callback(percent)

            if "TaskStatus" not in json_response:
                ret = RedfishClient.ERR_CODE_UNEXPECTED_RESPONSE
                err_msg = "Error: Missing 'TaskStatus' field"
                return (ret, err_msg, response)

            status = json_response["TaskStatus"]

            if (status != "OK") and ("Messages" not in json_response):
                ret = RedfishClient.ERR_CODE_GENERIC_ERROR
                err_msg = f'Error: Fail to execute the task - Taskstatus={status}'
                return (ret, err_msg, response)

            same_version = False
            err_detected = False
            aborted = False
            err_msg = ''

            for msg in json_response['Messages']:
                msg_id = msg['MessageId']

                if 'ResourceErrorsDetected' in msg_id:
                    err_detected = True
                    err_msg = msg['Message']
                elif 'TaskAborted' in msg_id:
                    aborted = True
                elif 'ComponentUpdateSkipped' in msg_id:
                    same_version = True
                    err_msg = msg['Message']

            if (status != 'OK'):
                ret = RedfishClient.ERR_CODE_GENERIC_ERROR
                if err_detected:
                    return (ret, f'Error: {err_msg}', response)
                elif aborted:
                    return (ret, 'Error: The task has been aborted', response)
                else:
                    err_msg = f'Error: Fail to execute the task - Taskstatus={status}'
                    return (ret, err_msg, response)
            elif same_version:
                    return (RedfishClient.ERR_CODE_IDENTICAL_IMAGE, err_msg, response)

            if percent is None:
                continue

            if (percent == 100):
                return (RedfishClient.ERR_CODE_OK, '', response)

            if (time.time() - start_tm > timeout):
                return (RedfishClient.ERR_CODE_TIMEOUT, 'Wait task completion timeout', response)

            time.sleep(sleep_timeout)

    '''
    Change login password

    Parameters:
      new_password    new password to change
    Return value:  (ret, error_msg)
      ret         return code
      error_msg   error message string
    '''
    def redfish_api_change_login_password(self, new_password, user=None):
        self.__logger.log_notice(f'Changing BMC password\n')

        cmd = self.__build_change_password_cmd(new_password, user)
        ret, response, error = self.exec_curl_cmd(cmd)

        if (ret != RedfishClient.ERR_CODE_OK):
            self.__logger.log_error(f'Fail to change login password: {error}\n')
            return (ret, f'Error: {error}')
        else:
            self.__logger.log_notice(f'Redfish response: \n')
            self.__log_json_response(response)
            try:
                json_response = json.loads(response)
                if 'error' in json_response:
                    msg = json_response['error']['message']
                    self.__logger.log_error(f'Fail to change login password: {msg}\n')

                    ret = RedfishClient.ERR_CODE_GENERIC_ERROR
                    return (ret, msg)
                elif 'Password@Message.ExtendedInfo' in json_response:
                    for info in json_response['Password@Message.ExtendedInfo']:
                        if info['MessageId'].endswith('Error'):
                            msg = info['Message']
                            self.__logger.log_error(f'Fail to change login password: {msg}\n')
                            resolution = info['Resolution']
                            self.__logger.log_error(f'Resolution: {resolution}\n')

                            ret = RedfishClient.ERR_CODE_GENERIC_ERROR

                            return (ret, msg)
                else:
                    self.__logger.log_notice(f'Password changed sucessfully\n')
                    ret = RedfishClient.ERR_CODE_OK
            except json.JSONDecodeError as e:
                ret = RedfishClient.ERR_CODE_INVALID_JSON_FORMAT
                return (ret, 'Error: Invalid JSON format')
            except Exception as e:
                ret = RedfishClient.ERR_CODE_UNEXPECTED_RESPONSE
                return (ret, 'Error: Unexpected response format')

        # Logout and re-login for admin user. Do not care about the result. Logout will invalidate token.
        # If it doesn't login successully, Redfish API call later on will do retry anyway.
        if user is None or user == 'admin': 
            self.logout()
            self.login()

        return (RedfishClient.ERR_CODE_OK, '')

    def redfish_api_set_component_update(self, comps):
        if comps:
            cmd = self.__build_set_component_update_cmd(comps)
        else:
            cmd = self.__build_set_component_update_reset_cmd()
        ret, response, error = self.exec_curl_cmd(cmd)

        if (ret == RedfishClient.ERR_CODE_OK):
            try:
                json_response = json.loads(response)

                if 'error' in json_response:
                    msg = json_response['error']['message']
                    self.__logger.log_error(f'{msg}\n')

                    ret = RedfishClient.ERR_CODE_GENERIC_ERROR
                    return (ret, msg)
                elif 'ForceUpdate@Message.ExtendedInfo' in json_response:
                    for info in json_response['ForceUpdate@Message.ExtendedInfo']:
                        if info['MessageId'].endswith('Error'):
                            msg = info['Message']
                            self.__logger.log_error(f'{msg}\n')
                            resolution = info['Resolution']
                            self.__logger.log_error(f'Resolution: {resolution}\n')

                            ret = RedfishClient.ERR_CODE_GENERIC_ERROR

                            return (ret, msg)
                else:
                    ret = RedfishClient.ERR_CODE_OK
            except json.JSONDecodeError as e:
                ret = RedfishClient.ERR_CODE_INVALID_JSON_FORMAT
            except Exception as e:
                ret = RedfishClient.ERR_CODE_UNEXPECTED_RESPONSE

        return (RedfishClient.ERR_CODE_OK, '')
