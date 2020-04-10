#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""

Cisco DNA Center Command Runner

Copyright (c) 2019 Cisco and/or its affiliates.

This software is licensed to you under the terms of the Cisco Sample
Code License, Version 1.1 (the "License"). You may obtain a copy of the
License at

               https://developer.cisco.com/docs/licenses

All use of the material herein must be in accordance with the terms of
the License. All rights not expressly granted by the License are
reserved. Unless required by applicable law or agreed to separately in
writing, software distributed under the License is distributed on an "AS
IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
or implied.

"""

__author__ = "Gabriel Zapodeanu TME, ENB"
__email__ = "gzapodea@cisco.com"
__version__ = "0.1.0"
__copyright__ = "Copyright (c) 2019 Cisco and/or its affiliates."
__license__ = "Cisco Sample Code License, Version 1.1"


import requests
import json
import time
import urllib3
import utils

from urllib3.exceptions import InsecureRequestWarning  # for insecure https warnings
from requests.auth import HTTPBasicAuth  # for Basic Auth

from config import DNAC_URL, DNAC_PASS, DNAC_USER


urllib3.disable_warnings(InsecureRequestWarning)  # disable insecure https warnings

DNAC_AUTH = HTTPBasicAuth(DNAC_USER, DNAC_PASS)


def pprint(json_data):
    """
    Pretty print JSON formatted data
    :param json_data: data to pretty print
    :return:
    """
    print(json.dumps(json_data, indent=4, separators=(' , ', ' : ')))


def get_dnac_jwt_token(dnac_auth):
    """
    Create the authorization token required to access DNA C
    Call to DNA C - /api/system/v1/auth/login
    :param dnac_auth - DNA C Basic Auth string
    :return: DNA C JWT token
    """
    url = DNAC_URL + '/dna/system/api/v1/auth/token'
    header = {'content-type': 'application/json'}
    response = requests.post(url, auth=dnac_auth, headers=header, verify=False)
    dnac_jwt_token = response.json()['Token']
    return dnac_jwt_token


def get_all_device_info(dnac_jwt_token):
    """
    The function will return all network devices info
    :param dnac_jwt_token: Cisco DNA Center token
    :return: DNA C device inventory info
    """
    url = DNAC_URL + '/dna/intent/api/v1/network-device'
    header = {'content-type': 'application/json', 'x-auth-token': dnac_jwt_token}
    all_device_response = requests.get(url, headers=header, verify=False)
    all_device_info = all_device_response.json()
    return all_device_info['response']


def get_device_info(device_id, dnac_jwt_token):
    """
    This function will retrieve all the information for the device with the DNA C device id
    :param device_id: DNA C device_id
    :param dnac_jwt_token: Cisco DNA Center token
    :return: device info
    """
    url = DNAC_URL + '/dna/intent/api/v1/network-device?id=' + device_id
    header = {'content-type': 'application/json', 'x-auth-token': dnac_jwt_token}
    device_response = requests.get(url, headers=header, verify=False)
    device_info = device_response.json()
    return device_info['response'][0]


def delete_device(device_id, dnac_jwt_token):
    """
    This function will delete the device with the {device_id} from the DNA Center inventory
    :param device_id: DNA C device_id
    :param dnac_jwt_token: Cisco DNA Center token
    :return: delete status
    """
    url = DNAC_URL + '/dna/intent/api/v1/network-device/' + device_id
    header = {'content-type': 'application/json', 'x-auth-token': dnac_jwt_token}
    response = requests.delete(url, headers=header, verify=False)
    delete_response = response.json()
    delete_status = delete_response['response']
    return delete_status


def get_project_id(project_name, dnac_jwt_token):
    """
    This function will retrieve the CLI templates project id for the project with the name {project_name}
    :param project_name: CLI project name
    :param dnac_jwt_token: Cisco DNA Center token
    :return: project id
    """
    url = DNAC_URL + '/dna/intent/api/v1/template-programmer/project?name=' + project_name
    header = {'content-type': 'application/json', 'x-auth-token': dnac_jwt_token}
    response = requests.get(url, headers=header, verify=False)
    project_json = response.json()
    project_id = project_json[0]['id']
    return project_id


def create_project(project_name, dnac_jwt_token):
    """
    This function will create a new project with the name {project_name}.
    - if the project exists, return the project id
    - if the project does not exist it will create a new project, waiting for the task to be completed
     and return the project id
    :param project_name: project name
    :param dnac_jwt_token: Cisco DNA Center token
    :return: project id, or none if creating a new project fails
    """

    # check if project exists
    url = DNAC_URL + '/dna/intent/api/v1/template-programmer/project?name=' + project_name
    header = {'content-type': 'application/json', 'x-auth-token': dnac_jwt_token}
    response = requests.get(url, headers=header, verify=False)
    project_json = response.json()
    # if project does not exist, project_json value is []. We need to create the project
    if project_json == []:
        # project does not exist
        payload = {'name': project_name}
        url = DNAC_URL + '/dna/intent/api/v1/template-programmer/project'
        header = {'content-type': 'application/json', 'x-auth-token': dnac_jwt_token}
        response = requests.post(url, data=json.dumps(payload), headers=header, verify=False)
        task_json = response.json()
        task_info = task_json['response']
        task_id = task_info['taskId']
        task_result = check_task_id_status(task_id, dnac_jwt_token)
        project_id = task_result['data']
    else:
        # project exists
        project_id = project_json[0]['id']
    return project_id


def delete_project(project_name, dnac_jwt_token):
    """
    This function will retrieve the CLI templates project id for the project with the name {project_name}
    :param project_name: CLI project name
    :param dnac_jwt_token: Cisco DNA Center token
    :return: project id
    """
    project_id = get_project_id(project_name, dnac_jwt_token)
    url = DNAC_URL + '/dna/intent/api/v1/template-programmer/project/' + project_id
    header = {'content-type': 'application/json', 'x-auth-token': dnac_jwt_token}
    response = requests.delete(url, headers=header, verify=False)


def get_project_info(project_name, dnac_jwt_token):
    """
    This function will retrieve all templates associated with the project with the name {project_name}
    :param project_name: project name
    :param dnac_jwt_token: Cisco DNA Center token
    :return: list of all templates, including names and ids
    """
    url = DNAC_URL + '/dna/intent/api/v1/template-programmer/project?name=' + project_name
    header = {'content-type': 'application/json', 'x-auth-token': dnac_jwt_token}
    response = requests.get(url, headers=header, verify=False)
    project_json = response.json()
    template_list = project_json[0]['templates']
    return template_list


def create_commit_template(template_name, project_name, cli_template, dnac_jwt_token):
    """
    This function will create and commit a CLI template, under the project with the name {project_name}, with the the text content
    {cli_template}
    :param template_name: CLI template name
    :param project_name: Project name
    :param cli_template: CLI template text content
    :param dnac_jwt_token: Cisco DNA Center token
    :return:
    """
    project_id = get_project_id(project_name, dnac_jwt_token)

    # prepare the template param to sent to DNA C
    payload = {
            "name": template_name,
            "description": "Remote router configuration",
            "tags": [],
            "author": "admin",
            "deviceTypes": [
                {
                    "productFamily": "Routers"
                },
                {
                    "productFamily": "Switches and Hubs"
                }
            ],
            "softwareType": "IOS-XE",
            "softwareVariant": "XE",
            "softwareVersion": "",
            "templateContent": cli_template,
            "rollbackTemplateContent": "",
            "templateParams": [],
            "rollbackTemplateParams": [],
            "parentTemplateId": project_id
        }

    # check and delete older versions of the template
    # template_id = get_template_id(template_name, project_name, dnac_jwt_token)
    # if template_id:
    #    delete_template(template_name, project_name, dnac_jwt_token)

    # create the new template
    url = DNAC_URL + '/dna/intent/api/v1/template-programmer/project/' + project_id + '/template'
    header = {'content-type': 'application/json', 'x-auth-token': dnac_jwt_token}
    response = requests.post(url, data=json.dumps(payload), headers=header, verify=False)

    # get the template id
    template_id = get_template_id(template_name, project_name, dnac_jwt_token)

    # commit template
    commit_template(template_id, 'committed by Python script', dnac_jwt_token)


def commit_template(template_id, comments, dnac_jwt_token):
    """
    This function will commit the template with the template id {template_id}
    :param template_id: template id
    :param comments: text with comments
    :param dnac_jwt_token: Cisco DNA Center token
    :return:
    """
    url = DNAC_URL + '/dna/intent/api/v1/template-programmer/template/version'
    payload = {
            "templateId": template_id,
            "comments": comments
        }
    header = {'content-type': 'application/json', 'x-auth-token': dnac_jwt_token}
    response = requests.post(url, data=json.dumps(payload), headers=header, verify=False)


def update_commit_template(template_name, project_name, cli_template, dnac_jwt_token):
    """
    This function will update an existing template
    :param template_name: template name
    :param project_name: project name
    :param cli_template: CLI template text content
    :param dnac_jwt_token: Cisco DNA Center token
    :return:
    """
    # get the project id
    project_id = get_project_id(project_name, dnac_jwt_token)

    # get the template id
    template_id = get_template_id(template_name, project_name, dnac_jwt_token)
    url = DNAC_URL + '/dna/intent/api/v1/template-programmer/template'

    # prepare the template param to sent to DNA C
    payload = {
        "name": template_name,
        "description": "Remote router configuration",
        "tags": [],
        "id": template_id,
        "author": "admin",
        "deviceTypes": [
            {
                "productFamily": "Routers"
            },
            {
                "productFamily": "Switches and Hubs"
            }
        ],
        "softwareType": "IOS-XE",
        "softwareVariant": "XE",
        "softwareVersion": "",
        "templateContent": cli_template,
        "rollbackTemplateContent": "",
        "templateParams": [],
        "rollbackTemplateParams": [],
        "parentTemplateId": project_id
    }
    header = {'content-type': 'application/json', 'x-auth-token': dnac_jwt_token}
    response = requests.put(url, data=json.dumps(payload), headers=header, verify=False)
    print(response.text)
    # commit template
    response = commit_template(template_id, 'committed by Python script', dnac_jwt_token)
    print(response.text)


def upload_template(template_name, project_name, cli_template, dnac_jwt_token):
    """
    This function will create, or will update an existing template, and deploy the new template
    :param template_name: template name
    :param project_name: project name
    :param cli_template: CLI template text content
    :param dnac_jwt_token: Cisco DNA Center token
    :return:
    """
    template_id = get_template_id(template_name, project_name, dnac_jwt_token)
    if template_id:
        update_commit_template(template_name, project_name, cli_template, dnac_jwt_token)
    else:
        create_commit_template(template_name, project_name, cli_template, dnac_jwt_token)


def delete_template(template_name, project_name, dnac_jwt_token):
    """
    This function will delete the template with the name {template_name}
    :param template_name: template name
    :param project_name: Project name
    :param dnac_jwt_token: Cisco DNA Center token
    :return:
    """
    template_id = get_template_id(template_name, project_name, dnac_jwt_token)
    url = DNAC_URL + '/dna/intent/api/v1/template-programmer/template/' + template_id
    header = {'content-type': 'application/json', 'x-auth-token': dnac_jwt_token}
    response = requests.delete(url, headers=header, verify=False)


def get_all_template_info(dnac_jwt_token):
    """
    This function will return the info for all CLI templates existing on DNA C, including all their versions
    :param dnac_jwt_token: Cisco DNA Center token
    :return: all info for all templates
    """
    url = DNAC_URL + '/dna/intent/api/v1/template-programmer/template'
    header = {'content-type': 'application/json', 'x-auth-token': dnac_jwt_token}
    response = requests.get(url, headers=header, verify=False)
    all_template_list = response.json()
    return all_template_list


def get_template_name_info(template_name, project_name, dnac_jwt_token):
    """
    This function will return the info for the CLI template with the name {template_name}
    :param template_name: template name
    :param project_name: Project name
    :param dnac_jwt_token: Cisco DNA Center token
    :return: all info for all templates
    """
    template_id = get_template_id(template_name, project_name, dnac_jwt_token)
    url = DNAC_URL + '/dna/intent/api/v1/template-programmer/template/' + template_id
    header = {'content-type': 'application/json', 'x-auth-token': dnac_jwt_token}
    response = requests.get(url, headers=header, verify=False)
    template_json = response.json()
    return template_json


def get_template_id(template_name, project_name, dnac_jwt_token):
    """
    This function will return the latest version template id for the DNA C template with the name {template_name},
    part of the project with the name {project_name}
    :param template_name: name of the template
    :param project_name: Project name
    :param dnac_jwt_token: Cisco DNA Center token
    :return: DNA C template id
    """
    template_list = get_project_info(project_name, dnac_jwt_token)
    template_id = None
    for template in template_list:
        if template['name'] == template_name:
            template_id = template['id']
    return template_id


def get_template_id_version(template_name, project_name, dnac_jwt_token):
    """
    This function will return the latest version template id for the DNA C template with the name {template_name},
    part of the project with the name {project_name}
    :param template_name: name of the template
    :param project_name: Project name
    :param dnac_jwt_token: Cisco DNA Center token
    :return: DNA C template id for the last version
    """
    project_id = get_project_id(project_name, dnac_jwt_token)
    url = DNAC_URL + '/dna/intent/api/v1/template-programmer/template?projectId=' + project_id + '&includeHead=false'
    header = {'content-type': 'application/json', 'x-auth-token': dnac_jwt_token}
    response = requests.get(url, headers=header, verify=False)
    project_json = response.json()
    for template in project_json:
        if template['name'] == template_name:
            version = 0
            versions_info = template['versionsInfo']
            for ver in versions_info:
                if int(ver['version']) > version:
                    template_id_ver = ver['id']
                    version = int(ver['version'])
    return template_id_ver


def send_deploy_template(template_name, project_name, device_name, dnac_jwt_token):
    """
    This function will deploy the template with the name {template_name} to the network device with the name
    {device_name}
    :param template_name: template name
    :param project_name: project name
    :param device_name: device hostname
    :param dnac_jwt_token: Cisco DNA Center token
    :return: the deployment task id
    """
    template_id = get_template_id_version(template_name, project_name, dnac_jwt_token)
    payload = {
            "templateId": template_id,
            "targetInfo": [
                {
                    "id": device_name,
                    "type": "MANAGED_DEVICE_HOSTNAME",
                    "params": {}
                }
            ]
        }
    url = DNAC_URL + '/dna/intent/api/v1/template-programmer/template/deploy'
    header = {'content-type': 'application/json', 'x-auth-token': dnac_jwt_token}
    deployment = requests.post(url, headers=header, data=json.dumps(payload), verify=False)
    deployment_json = deployment.json()
    depl_task_id = deployment_json["deploymentId"].split(' ')[-1]
    return depl_task_id


def check_template_deployment_status(depl_task_id, dnac_jwt_token):
    """
    This function will check the result for the deployment of the CLI template with the id {depl_task_id}
    :param depl_task_id: template deployment id
    :param dnac_jwt_token: Cisco DNA Center token
    :return: status - {SUCCESS} or {FAILURE}
    """
    url = DNAC_URL + '/dna/intent/api/v1/template-programmer/template/deploy/status/' + depl_task_id
    header = {'content-type': 'application/json', 'x-auth-token': dnac_jwt_token}
    response = requests.get(url, headers=header, verify=False)
    response_json = response.json()
    deployment_status = response_json["status"]
    return deployment_status


def get_client_info(client_ip, dnac_jwt_token):
    """
    This function will retrieve all the information from the client with the IP address
    Deprecated, do not use
    :param client_ip: client IPv4 address
    :param dnac_jwt_token: Cisco DNA Center token
    :return: client info, or {None} if client does not found
    """
    url = DNAC_URL + '/api/v1/host?hostIp=' + client_ip
    header = {'content-type': 'application/json', 'x-auth-token': dnac_jwt_token}
    response = requests.get(url, headers=header, verify=False)
    client_json = response.json()
    try:
        client_info = client_json['response'][0]
        return client_info
    except:
        return None


def locate_client_ip(client_ip, dnac_jwt_token):
    """
    Locate a wired client device in the infrastructure by using the client IP address
    Call to DNA C - api/v1/host?hostIp={client_ip}
    Deprecated, do not use
    :param client_ip: Client IP Address
    :param dnac_jwt_token: Cisco DNA Center token
    :return: hostname, interface_name, vlan_id, or None, if the client does not exist
    """

    client_info = get_client_info(client_ip, dnac_jwt_token)
    if client_info is not None:
        hostname = client_info['connectedNetworkDeviceName']
        interface_name = client_info['connectedInterfaceName']
        vlan_id = client_info['vlanId']
        return hostname, interface_name, vlan_id
    else:
        return None


def get_device_id_name(device_name, dnac_jwt_token):
    """
    This function will find the DNA C device id for the device with the name {device_name}
    :param device_name: device hostname
    :param dnac_jwt_token: Cisco DNA Center token
    :return:
    """
    device_id = None
    device_list = get_all_device_info(dnac_jwt_token)
    for device in device_list:
        if device['hostname'] == device_name:
            device_id = device['id']
    return device_id


def get_device_status(device_name, dnac_jwt_token):
    """
    This function will return the reachability status for the network device with the name {device_name}
    :param device_name: device name
    :param dnac_jwt_token: Cisco DNA Center token
    :return: status - {UNKNOWN} to locate a device in the database,
                      {SUCCESS} device reachable
                      {FAILURE} device not reachable
    """
    device_id = get_device_id_name(device_name, dnac_jwt_token)
    if device_id is None:
        return 'UNKNOWN'
    else:
        device_info = get_device_info(device_id, dnac_jwt_token)
        if device_info['reachabilityStatus'] == 'Reachable':
            return 'SUCCESS'
        else:
            return 'FAILURE'


def get_device_management_ip(device_name, dnac_jwt_token):
    """
    This function will find out the management IP address for the device with the name {device_name}
    :param device_name: device name
    :param dnac_jwt_token: Cisco DNA Center token
    :return: the management ip address
    """
    device_ip = None
    device_list = get_all_device_info(dnac_jwt_token)
    for device in device_list:
        if device['hostname'] == device_name:
            device_ip = device['managementIpAddress']
    return device_ip


def get_device_id_sn(device_sn, dnac_jwt_token):
    """
    The function will return the DNA C device id for the device with serial number {device_sn}
    :param device_sn: network device SN
    :param dnac_jwt_token: Cisco DNA Center token
    :return: DNA C device id
    """
    url = DNAC_URL + '/dna/intent/api/v1/network-device/serial-number/' + device_sn
    header = {'content-type': 'application/json', 'x-auth-token': dnac_jwt_token}
    device_response = requests.get(url, headers=header, verify=False)
    device_info = device_response.json()
    device_id = device_info['response']['id']
    return device_id


def sync_device(device_name, dnac_jwt_token):
    """
    This function will sync the device configuration from the device with the name {device_name}
    :param device_name: device hostname
    :param dnac_jwt_token: Cisco DNA Center token
    :return: the response status code, 202 if sync initiated, and the task id
    """
    device_id = get_device_id_name(device_name, dnac_jwt_token)
    param = [device_id]
    url = DNAC_URL + '/dna/intent/api/v1/network-device/sync?forceSync=true'
    header = {'content-type': 'application/json', 'x-auth-token': dnac_jwt_token}
    sync_response = requests.put(url, data=json.dumps(param), headers=header, verify=False)
    task = sync_response.json()['response']['taskId']
    return sync_response.status_code, task


def check_task_id_status(task_id, dnac_jwt_token):
    """
    This function will check the status of the task with the id {task_id}
    :param task_id: task id
    :param dnac_jwt_token: Cisco DNA Center token
    :return: status - {SUCCESS} or {FAILURE}, and the task status message
    """
    # loop until the task is completed, check status every second
    task_result = ''

    while task_result == '':
        time.sleep(1)
        url = DNAC_URL + '/dna/intent/api/v1/task/' + task_id
        header = {'content-type': 'application/json', 'x-auth-token': dnac_jwt_token}
        task_response = requests.get(url, headers=header, verify=False)
        task_json = task_response.json()
        task_status = task_json['response']
        print(task_status)
        if 'endTime' in task_status.keys():
            return task_status


def check_task_id_output(task_id, dnac_jwt_token):
    """
    This function will check the status of the task with the id {task_id}.
    Loop one seconds increments until task is completed.
    :param task_id: task id
    :param dnac_jwt_token: Cisco DNA Center token
    :return: status - {SUCCESS} or {FAILURE}
    """
    url = DNAC_URL + '/dna/intent/api/v1/task/' + task_id
    header = {'content-type': 'application/json', 'x-auth-token': dnac_jwt_token}
    completed = 'no'
    while completed == 'no':
        try:
            task_response = requests.get(url, headers=header, verify=False)
            task_json = task_response.json()
            task_output = task_json['response']
            # check if file id available in output
            file_info = json.loads(task_output['progress'])
            completed = 'yes'
        finally:
            time.sleep(1)
    return task_output


def create_path_trace(src_ip, dest_ip, dnac_jwt_token):
    """
    This function will create a new Path Trace between the source IP address {src_ip} and the
    destination IP address {dest_ip}
    :param src_ip: Source IP address
    :param dest_ip: Destination IP address
    :param dnac_jwt_token: Cisco DNA Center token
    :return: DNA C path visualisation id
    """

    param = {
        'destIP': dest_ip,
        'periodicRefresh': False,
        'sourceIP': src_ip
    }

    url = DNAC_URL + '/dna/intent/api/v1/flow-analysis'
    header = {'accept': 'application/json', 'content-type': 'application/json', 'x-auth-token': dnac_jwt_token}
    path_response = requests.post(url, data=json.dumps(param), headers=header, verify=False)
    path_json = path_response.json()
    path_id = path_json['response']['flowAnalysisId']
    return path_id


def get_path_trace_info(path_id, dnac_jwt_token):
    """
    This function will return the path trace details for the path visualisation {id}
    :param path_id: DNA C path visualisation id
    :param dnac_jwt_token: Cisco DNA Center token
    :return: Path visualisation status, and the details in a list [device,interface_out,interface_in,device...]
    """

    url = DNAC_URL + '/dna/intent/api/v1/flow-analysis/' + path_id
    header = {'accept': 'application/json', 'content-type': 'application/json', 'x-auth-token': dnac_jwt_token}
    path_response = requests.get(url, headers=header, verify=False)
    path_json = path_response.json()
    path_info = path_json['response']
    path_status = path_info['request']['status']
    path_list = []
    if path_status == 'COMPLETED':
        network_info = path_info['networkElementsInfo']
        path_list.append(path_info['request']['sourceIP'])
        for elem in network_info:
            try:
                path_list.append(elem['ingressInterface']['physicalInterface']['name'])
            except:
                pass
            try:
                path_list.append(elem['name'])
            except:
                pass
            try:
                path_list.append(elem['egressInterface']['physicalInterface']['name'])
            except:
                pass
        path_list.append(path_info['request']['destIP'])
    return path_status, path_list


def check_ipv4_network_interface(ip_address, dnac_jwt_token):
    """
    This function will check if the provided IPv4 address is configured on any network interfaces
    :param ip_address: IPv4 address
    :param dnac_jwt_token: Cisco DNA Center token
    :return: None, or device_hostname and interface_name
    """
    url = DNAC_URL + '/dna/intent/api/v1/interface/ip-address/' + ip_address
    header = {'content-type': 'application/json', 'x-auth-token': dnac_jwt_token}
    response = requests.get(url, headers=header, verify=False)
    response_json = response.json()
    try:
        response_info = response_json['response'][0]
        interface_name = response_info['portName']
        device_id = response_info['deviceId']
        device_info = get_device_info(device_id, dnac_jwt_token)
        device_hostname = device_info['hostname']
        return device_hostname, interface_name
    except:
        device_info = get_device_info_ip(ip_address, dnac_jwt_token)  # required for AP's
        device_hostname = device_info['hostname']
        return device_hostname, ''


def get_device_info_ip(ip_address, dnac_jwt_token):
    """
    This function will retrieve the device information for the device with the management IPv4 address {ip_address}
    :param ip_address: device management ip address
    :param dnac_jwt_token: Cisco DNA Center token
    :return: device information, or None
    """
    url = DNAC_URL + '/dna/intent/api/v1/network-device/ip-address/' + ip_address
    header = {'content-type': 'application/json', 'x-auth-token': dnac_jwt_token}
    response = requests.get(url, headers=header, verify=False)
    response_json = response.json()
    device_info = response_json['response']
    if 'errorCode' == 'Not found':
        return None
    else:
        return device_info


def get_legit_cli_command_runner(dnac_jwt_token):
    """
    This function will get all the legit CLI commands supported by the {command runner} APIs
    :param dnac_jwt_token: Cisco DNA Center token
    :return: list of CLI commands
    """
    url = DNAC_URL + '/dna/intent/api/v1/network-device-poller/cli/legit-reads'
    header = {'content-type': 'application/json', 'x-auth-token': dnac_jwt_token}
    response = requests.get(url, headers=header, verify=False)
    response_json = response.json()
    cli_list = response_json['response']
    return cli_list


def get_content_file_id(file_id, dnac_jwt_token):
    """
    This function will download the file specified by the {file_id}
    :param file_id: file id
    :param dnac_jwt_token: Cisco DNA Center token
    :return: file
    """
    url = DNAC_URL + '/dna/intent/api/v1/file/' + file_id
    header = {'content-type': 'application/json', 'x-auth-token': dnac_jwt_token}
    response = requests.get(url, headers=header, verify=False, stream=True)
    response_json = response.json()
    return response_json


def get_output_command_runner(command, device_name, dnac_jwt_token):
    """
    This function will return the output of the CLI command specified in the {command}, sent to the device with the
    hostname {device}
    :param command: CLI command
    :param device_name: device hostname
    :param dnac_jwt_token: Cisco DNA Center token
    :return: file with the command output
    """

    # get the Cisco DNA Center device id
    device_id = get_device_id_name(device_name, dnac_jwt_token)

    # get the Cisco DNA Center task id that will execute the CLI command runner
    payload = {
        "commands": [command],
        "deviceUuids": [device_id],
        "timeout": 0
        }
    url = DNAC_URL + '/dna/intent/api/v1/network-device-poller/cli/read-request'
    header = {'content-type': 'application/json', 'x-auth-token': dnac_jwt_token}
    response = requests.post(url, data=json.dumps(payload), headers=header, verify=False)
    response_json = response.json()
    try:
        task_id = response_json['response']['taskId']
    except:
        print('\n' + response_json['response']['detail'])
        return

    # get task id status
    # wait 2 second for the command runner task to be started
    time.sleep(2)
    task_result = check_task_id_output(task_id, dnac_jwt_token)
    file_info = json.loads(task_result['progress'])
    file_id = file_info['fileId']

    # get output from file
    time.sleep(2)  # wait for 2 seconds for the file to be ready
    file_output = get_content_file_id(file_id, dnac_jwt_token)
    command_responses = file_output[0]['commandResponses']
    if command_responses['SUCCESS'] != {}:
        command_output = command_responses['SUCCESS'][command]
    elif command_responses['FAILURE'] != {}:
        command_output = command_responses['FAILURE'][command]
    else:
        command_output = command_responses['BLACKLISTED'][command]
    return command_output


def get_all_configs(dnac_jwt_token):
    """
    This function will retrieve all the devices configurations
    :param dnac_jwt_token: Cisco DNA Center token
    :return: Return all config files in a list
    """
    url = DNAC_URL + '/dna/intent/api/v1/network-device/config'
    header = {'content-type': 'application/json', 'x-auth-token': dnac_jwt_token}
    response = requests.get(url, headers=header, verify=False)
    config_json = response.json()
    config_files = config_json['response']
    return config_files


def get_device_config(device_name, dnac_jwt_token):
    """
    This function will get the configuration file for the device with the name {device_name}
    :param device_name: device hostname
    :param dnac_jwt_token: Cisco DNA Center token
    :return: configuration file
    """
    device_id = get_device_id_name(device_name, dnac_jwt_token)
    url = DNAC_URL + '/dna/intent/api/v1/network-device/' + device_id + '/config'
    header = {'content-type': 'application/json', 'x-auth-token': dnac_jwt_token}
    response = requests.get(url, headers=header, verify=False)
    config_json = response.json()
    config_file = config_json['response']
    return config_file


def check_ipv4_address(ipv4_address, dnac_jwt_token):
    """
    This function will find if the IPv4 address is configured on any network interfaces or used by any hosts.
    :param ipv4_address: IPv4 address
    :param dnac_jwt_token: Cisco DNA Center token
    :return: True/False
    """
    # check against network devices interfaces
    try:
        device_info = check_ipv4_network_interface(ipv4_address, dnac_jwt_token)
        return True
    except:
        # check against any hosts
        try:
            client_info = get_client_info(ipv4_address, dnac_jwt_token)
            if client_info is not None:
                return True
        except:
            pass
    return False


def check_ipv4_address_configs(ipv4_address, dnac_jwt_token):
    """
    This function will verify if the IPv4 address is present in any of the configurations of any devices
    :param ipv4_address: IPv4 address
    :param dnac_jwt_token: Cisco DNA Center token
    :return: True/False
    """
    url = DNAC_URL + '/dna/intent/api/v1/network-device/config'
    header = {'content-type': 'application/json', 'x-auth-token': dnac_jwt_token}
    response = requests.get(url, headers=header, verify=False)
    config_json = response.json()
    config_files = config_json['response']
    for config in config_files:
        run_config = config['runningConfig']
        if ipv4_address in run_config:
            return True
    return False


def check_ipv4_duplicate(config_file):
    """
    This function will:
      - load a file with a configuration to be deployed to a network device
      - identify the IPv4 addresses that will be configured on interfaces
      - search in the DNA Center database if these IPV4 addresses are configured on any interfaces
      - find if any clients are using the IPv4 addresses
      - Determine if deploying the configuration file will create an IP duplicate
    :param config_file: configuration file name
    :return True/False
    """

    # open file with the template
    cli_file = open(config_file, 'r')

    # read the file
    cli_config = cli_file.read()

    ipv4_address_list = utils.identify_ipv4_address(cli_config)

    # get the DNA Center Auth token

    dnac_token = get_dnac_jwt_token(DNAC_AUTH)

    # check each address against network devices and clients database
    # initialize duplicate_ip

    duplicate_ip = False
    for ipv4_address in ipv4_address_list:

        # check against network devices interfaces

        try:
            device_info = check_ipv4_network_interface(ipv4_address, dnac_token)
            duplicate_ip = True
        except:
            pass

        # check against any hosts

        try:
            client_info = get_client_info(ipv4_address, dnac_token)
            if client_info is not None:
                duplicate_ip = True
        except:
            pass

    if duplicate_ip:
        return True
    else:
        return False


def get_device_detail(device_name, epoch_time, dnac_jwt_token):
    """
    This function will call the device health intent API and return device management interface IPv4 address,
    serial number, family, software version, device health score, ... for the device with the name {device_name}
    :param device_name: device hostname
    :param epoch_time: epoch time including msec
    :param dnac_jwt_token: Cisco DNA Center token
    :return: detailed network device information
    """
    device_id = get_device_id_name(device_name, dnac_jwt_token)
    url = DNAC_URL + '/dna/intent/api/v1/device-detail?timestamp=' + str(epoch_time) + '&searchBy=' + device_id
    url += '&identifier=uuid'
    header = {'content-type': 'application/json', 'x-auth-token': dnac_jwt_token}
    response = requests.get(url, headers=header, verify=False)
    device_detail_json = response.json()
    device_detail = device_detail_json['response']
    return device_detail


def pnp_get_device_count(device_state, dnac_jwt_token):
    """
    This function will return the count of the PnP devices in the state {state}
    :param device_state: device state, example 'Unclaimed'
    :param dnac_jwt_token: Cisco DNA Center token
    :return: device count
    """
    url = DNAC_URL + '/dna/intent/api/v1/onboarding/pnp-device/count'
    payload = {'state': device_state}
    header = {'content-type': 'application/json', 'x-auth-token': dnac_jwt_token}
    response = requests.get(url, headers=header, data=json.dumps(payload), verify=False)
    pnp_device_count = response.json()
    return pnp_device_count['response']


def pnp_get_device_list(dnac_jwt_token):
    """
    This function will retrieve the PnP device list info
    :param dnac_jwt_token: Cisco DNA Center token
    :return: PnP device info
    """
    url = DNAC_URL + '/dna/intent/api/v1/onboarding/pnp-device'
    header = {'content-type': 'application/json', 'x-auth-token': dnac_jwt_token}
    response = requests.get(url, headers=header, verify=False)
    pnp_device_json = response.json()
    return pnp_device_json


def pnp_claim_ap_site(device_id, floor_id, rf_profile, dnac_jwt_token):
    """
    This function will delete claim the AP with the {device_id} to the floor with the {floor_id}
    :param device_id: Cisco DNA C device id
    :param floor_id: Cisco DNA C floor id
    :param rf_profile: RF profile - options - "LOW", "TYPICAL", "HIGH"
    :param dnac_jwt_token: Cisco DNA C token
    :return: claim operation status
    """
    payload = {
        "type": "AccessPoint",
        "siteId": floor_id,
        "deviceId": device_id,
        "rfProfile": rf_profile
        }
    url = DNAC_URL + '/dna/intent/api/v1/onboarding/pnp-device/site-claim'
    header = {'content-type': 'application/json', 'x-auth-token': dnac_jwt_token}
    response = requests.post(url, headers=header, data=json.dumps(payload), verify=False)
    claim_status_json = response.json()
    claim_status = claim_status_json['response']
    return claim_status


def pnp_delete_provisioned_device(device_id, dnac_jwt_token):
    """
    This function will delete the provisioned device with the {device_id} from the PnP database
    :param device_id: Cisco DNA C device id
    :param dnac_jwt_token: Cisco DNA C token
    :return: delete opearation status
    """
    url = DNAC_URL + '/dna/intent/api/v1/onboarding/pnp-device/' + device_id
    header = {'content-type': 'application/json', 'x-auth-token': dnac_jwt_token}
    response = requests.delete(url, headers=header, verify=False)
    delete_status = response.json()
    return delete_status


def pnp_get_device_info(device_id, dnac_jwt_token):
    """
    This function will get the details for the a PnP device with the {device_id} from the PnP database
    :param device_id: Cisco DNA C device id
    :param dnac_jwt_token: Cisco DNA C token
    :return: device info in json format
    """
    url = DNAC_URL + '/dna/intent/api/v1/onboarding/pnp-device/' + device_id
    header = {'content-type': 'application/json', 'x-auth-token': dnac_jwt_token}
    response = requests.get(url, headers=header, verify=False)
    device_info_json = response.json()
    device_info = device_info_json['deviceInfo']
    return device_info


def get_physical_topology(ip_address, dnac_jwt_token):
    """
    This function will retrieve the physical topology for the device/client with the {ip_address}
    :param ip_address: device/interface IP address
    :param dnac_jwt_token: Cisco DNA C token
    :return: topology info - connected device hostname and interface
    """
    url = DNAC_URL + '/dna/intent/api/v1/topology/physical-topology'
    header = {'content-type': 'application/json', 'x-auth-token': dnac_jwt_token}
    response = requests.get(url, headers=header, verify=False)
    topology_json = response.json()['response']
    topology_nodes = topology_json['nodes']
    topology_links = topology_json['links']

    # try to identify the physical topology
    for link in topology_links:
        try:
            if link['startPortIpv4Address'] == ip_address:
                connected_port = link['endPortName']
                connected_device_id = link['target']
                for node in topology_nodes:
                    if node['id'] == connected_device_id:
                        connected_device_hostname = node['label']
                break
        except:
            connected_port = None
            connected_device_hostname = None
    return connected_device_hostname, connected_port

"""
dnac_auth = get_dnac_jwt_token(DNAC_AUTH)
project = create_project('test', dnac_auth)
input('nay key to continue ')
delete_project('test', dnac_auth)
"""