#!/usr/bin/env python3
# cf-404-assistant.py
# given account and region:
# lists all CF-enabled containers on account
# optionally disables and enables
# version: 0.0.1a
# Copyright 2019 Brian King
# License: Apache

from getpass import getpass
import json
import keyring
import logging
import os
import plac
import requests
import sys
import time
import uuid

def find_endpoints(auth_token, headers, region, desired_service="cloudServersOpenStack"):

    url = ("https://identity.api.rackspacecloud.com/v2.0/tokens/%s/endpoints" % auth_token)
    #region is always uppercase in the service catalog
    region = region.upper()
    raw_service_catalog = requests.get(url, headers=headers)
    raw_service_catalog.raise_for_status()
    the_service_catalog = raw_service_catalog.json()
    endpoints = the_service_catalog["endpoints"]

    for service in endpoints:
        if desired_service == service["name"] and region == service["region"]:
            desired_endpoint = service["publicURL"]

    return desired_endpoint

def getset_keyring_credentials(username=None, password=None):
    #Method to retrieve credentials from keyring.
    print (sys.version_info.major)
    username = keyring.get_password("ioni", "username")
    if username is None:
        if sys.version_info.major < 3:
            username = raw_input("Enter Rackspace Username: ")
            keyring.set_password("ioni", 'username', username)
            print ("Username value saved in keychain as ioni username.")
        elif sys.version_info.major >= 3:
            username = input("Enter Rackspace Username: ")
            keyring.set_password("ioni", 'username', username)
            print ("Username value saved in keychain as ioni username.")
    else:
        print ("Authenticating to Rackspace cloud as %s" % username)
    password = keyring.get_password("ioni", "password")
    if password is None:
        password = getpass("Enter Rackspace API key:")
        keyring.set_password("ioni", 'password' , password)
        print ("API key value saved in keychain as ioni password.")
    return username, password
# Request to authenticate using password
def get_auth_token(username,password):
    #setting up api call
    url = "https://identity.api.rackspacecloud.com/v2.0/tokens"
    headers = {'Content-type': 'application/json'}
    payload = {'auth':{'passwordCredentials':{'username': username,'password': password}}}
    payload2 = {'auth':{'RAX-KSKEY:apiKeyCredentials':{'username': username,'apiKey': password}}}

    #authenticating against the identity
    try:
        r = requests.post(url, headers=headers, json=payload)
    except requests.ConnectionError as e:
        print("Connection Error: Check your interwebs!")
        sys.exit()


    if r.status_code != 200:
        r = requests.post(url, headers=headers, json=payload2)
        if r.status_code != 200:
            print ("Error! API responds with %d" % r.status_code)
            print("Rerun the script and you will be prompted to re-enter username/password.")
            wipe_keyring_credentials(username, password)
            sys.exit()
        else:
            print("Authentication was successful!")
    elif r.status_code == 200:
        print("Authentication was successful!")

    #loads json reponse into data as a dictionary.
    data = r.json()
    #assign token and account variables with info from json response.
    auth_token = data["access"]["token"]["id"]

    headers = ({'content-type': 'application/json', 'Accept': 'application/json',
    'X-Auth-Token': auth_token})

    return auth_token, headers

def get_cdn_enabled_containers(cfcdn_endpoint, headers, region):
    print ("Checking for CDN-enabled Cloud Files in {}...".format(region))
    cdn_enabled_query = requests.get(url=cfcdn_endpoint, headers=headers)
    cdn_enabled_containers = cdn_enabled_query.json()
    num_cec = len(cdn_enabled_containers)
    print ("Found {} CDN-enabled containers in {}!".format(num_cec, region))
    return cdn_enabled_containers

def toggle_container(cfcdn_endpoint, cdn_enabled_containers, headers, region):
    # Used for disabling CDN
    headers["X-CDN-Enabled"] = "False"
    # FIXME: only for 191002-ord-0000708
    cecs_already_toggled = [ "ion", "LiveBall_Citizensbank",
    "LiveBall_Euromoneyplc", "LiveBall_Fdb", "LiveBall_Servicemaster" ]

    for cec in cdn_enabled_containers:
        cec_name = cec["name"]
        cec_url = "{}/{}".format(cfcdn_endpoint, cec_name )
        if (cec["cdn_enabled"]) and (cec["name"]) not in cecs_already_toggled:
            print ("Container {} is CDN-enabled, toggling...".format(cec_name))
            cdn_disable_req = requests.put(url=cec_url, headers=headers)
            cdn_disable_req.raise_for_status()
            if cdn_disable_req.status_code == 204:
                print (f"Successfully disabled CDN on container {cec_name}!"
                       f"Sleeping 5 seconds, then re-enabling!")
                time.sleep(5)
                print ("Done sleeping...enabling CDN on container {}!".format(cec_name))
                headers["X-CDN-Enabled"] = "True"
                cdn_enable_req = requests.put(url=cec_url, headers=headers)
                cdn_enable_req.raise_for_status()
                if cdn_enable_req.status_code == 204:
                    print (f"Successfully re-enabled CDN on container {cec_name}!")




@plac.annotations(
    region=plac.Annotation("Rackspace Cloud region")
                )

def main(region):

    username, password = getset_keyring_credentials()

    auth_token, headers = get_auth_token(username, password)

    cfcdn_endpoint = find_endpoints(auth_token, headers, region,
              desired_service="cloudFilesCDN")

    cdn_enabled_containers = get_cdn_enabled_containers(cfcdn_endpoint, headers, region)

    toggle_container(cfcdn_endpoint, cdn_enabled_containers, headers, region)

if __name__ == '__main__':
    plac.call(main)