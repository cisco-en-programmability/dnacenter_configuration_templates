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
import urllib3
import time
import sys
import os
import logging
import datetime
import dnac_apis

from urllib3.exceptions import InsecureRequestWarning  # for insecure https warnings
from requests.auth import HTTPBasicAuth  # for Basic Auth

from config import DNAC_URL, DNAC_PASS, DNAC_USER

urllib3.disable_warnings(InsecureRequestWarning)  # disable insecure https warnings

DNAC_AUTH = HTTPBasicAuth(DNAC_USER, DNAC_PASS)


def main():
    """
    This script will load the file with the name {file_info}
    The file includes the information required to deploy the template. The network device hostname, the Cisco DNA Center
    project name, the configuration template file name.
    The application will:
     - verify if the project exists and create a new project if does not
     - update or upload the configuration template
     - commit the template
     - verify the device hostname is valid
     - deploy the template
     - verify completion and status of the template deployment
    :param template_info: the CLI command
    """

    # the local date and time when the code will start execution

    date_time = str(datetime.datetime.now().replace(microsecond=0))

    print('\n\nApplication "dnacenter_config_templates.py" Run Started: ' + date_time)

    # input data validation

    # open the file with the device, project and template info
    with open('template.txt', 'r') as f:
        data = f.read()
    template_info = json.loads(data)

    print('\nThe Cisco DNA Center Template information is: \n', template_info)
    device_hostname = template_info['device']
    project_name = template_info['project']
    template_name = template_info['template']

    # get a Cisco DNA Center auth token
    dnac_auth = dnac_apis.get_dnac_jwt_token(DNAC_AUTH)

    # check if existing project, if not create a new project
    project_id = dnac_apis.create_project(project_name, dnac_auth)
    if project_id == 'none':
        # unable to find or create the project
        print('\nUnable to create the project: ', project_name)
        return
    # continue with the project id
    print('\nThe project id for the the project with the name: ' + project_name + ' is: ' + project_id)


    date_time = str(datetime.datetime.now().replace(microsecond=0))
    print('\n\nEnd of Application "dnacenter_config_templates.py" Run: ' + date_time)
    return


if __name__ == "__main__":
    main()

"""
if __name__ == "__main__":
    sys.exit(main(sys.argv[0]))
"""