#!/usr/bin/env python

# DESCRIPTION:
# McAfee Web Gateway Cloud Service (WGCS) Logpuller Script.
#
# Script to get McAfee Web Gateway Cloud Service logs from McAfee SaaS-API.
# Logs are downloaded to 'OutputLog.$NowUnixEpoch$.csv' and can be forwarded
# to a remote syslog host or SIEM when 'syslogEnable' is set to 'True'.
# When forwarding is used the downloaded CSV is transformed into a JSON stream.
# Configure your syslog/SIEM input correspondingly.
#
# The script is using McAfee SaaS Message API ver. 5; Field reference:
# https://docs.mcafee.com/bundle/web-gateway-cloud-service-product-guide/page/GUID-BDF3E4F1-1625-4569-BE80-D528CE521BC1.html
#
# 
# CHANGELOG:
# 1.0  2020-05-02 - initial release (Happy Birthday Adam!)
#
################################################################################
# Copyright (C) 2020 Daniel Schindler, daniel.schindler@steag.com
#
# This program is free software; you can redistribute it and/or modify it under
# the terms of the GNU General Public License as published by the Free Software
# Foundation; either version 3 of the License, or (at your option) any later
# version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with
# this program; if not, see <http://www.gnu.org/licenses>.
################################################################################

from datetime import datetime, date
import os
import platform
import string
import sys
import time
import socket
import csv
import json
import StringIO
import requests
from requests.auth import HTTPBasicAuth
import ConfigParser
import io
import logging
import argparse

# small help for script; patch to custom configuration file can be passed
helper = argparse.ArgumentParser(description='''McAfee Web Gateway Cloud Service (WGCS) Log Puller Script.''')
helper.add_argument('--config', help='path to custom configuration file (default: <scriptname>.conf)', nargs='?', default=os.path.splitext(__file__)[0] + '.conf')
args = helper.parse_args()

# set path to custom config or default to $scriptname$.conf
config = args.config
# log will be $scriptname$.log
log = os.path.splitext(__file__)[0] + '.log'
try:
    os.remove(log)
except:
    pass

# set logging style 2020-05-03 00:51:02,954 <LEVEL>: <message> 
logging.basicConfig(format='%(asctime)s %(levelname)s: %(message)s', filename=log, level=logging.INFO)

# first log lines
logging.info('log='+log)
logging.info('config='+config)

# Path for request; effectively the search string for log messages
saasPath = '/mwg/api/reporting/forensic/$saasCustomerID$?filter.requestTimestampFrom=$requestTimestampFrom$&amp;filter.requestTimestampTo=$requestTimestampTo$&amp;order.0.requestTimestamp=asc'
## output file for downloaded CSV log entries
saasFilename = os.path.join(sys.path[0], 'OutputLog.$Now$.csv')
# first line of response should be this when API version 5 used:
fieldHeader = '"user_id","username","source_ip","http_action","server_to_client_bytes","client_to_server_bytes","requested_host","requested_path","result","virus","request_timestamp_epoch","request_timestamp","uri_scheme","category","media_type","application_type","reputation","last_rule","http_status_code","client_ip","location","block_reason","user_agent_product","user_agent_version","user_agent_comment","process_name","destination_ip","destination_port"'
# request header for CSV download and API version
requestHeaders = {'user-agent': 'logpuller/0.0.0.0', 'Accept': 'text/csv', 'x-mwg-api-version': '5'}
requestTimestampFrom = 0
chunkIncrement = 0
# terminate request if no response within connectionTimeout
connectionTimeout = 180
totalLines = 0
Now = int(time.time())
requestTimestampTo = Now

def readConfig(config):
    global saasCustomerID, saasUserID, saasPassword, saasHost, requestTimestampFrom, chunkIncrement, connectionTimeout, proxyURL, syslogEnable, syslogHost, syslogPort, syslogProto, syslogKeepCSV
    try:
        with open(config, 'r') as f:
            cfgfile = f.read()
            parser = ConfigParser.RawConfigParser(allow_no_value=True)
            # make option names case sensitive (https://docs.python.org/2/library/configparser.html#ConfigParser.RawConfigParser.optionxform)
            parser.optionxform = str
            parser.readfp(io.BytesIO(cfgfile))

            saasCustomerID = parser.getint('saas', 'saasCustomerID')
            logging.info('saasCustomerID='+str(saasCustomerID))

            saasUserID = parser.get('saas', 'saasUserID')
            logging.info('saasUserID='+saasUserID)

            saasPassword = parser.get('saas', 'saasPassword')
            # do not log saasPassword

            saasHost = parser.get('saas', 'saasHost')
            logging.info('saasHost='+saasHost)

            requestTimestampFrom = parser.getint('request', 'requestTimestampFrom')
            logging.info('requestTimestampFrom='+str(requestTimestampFrom))

            chunkIncrement = parser.getint('request', 'chunkIncrement')
            logging.info('chunkIncrement='+str(chunkIncrement))

            connectionTimeout = parser.getint('request', 'connectionTimeout')
            logging.info('connectionTimeout='+str(connectionTimeout))

            proxyURL = parser.get('proxy', 'proxyURL')
            # do not log proxyURL - might contain user/password

            syslogEnable = parser.getboolean('syslog', 'syslogEnable')
            logging.info('syslogEnable='+str(syslogEnable))

            syslogHost = parser.get('syslog', 'syslogHost')
            logging.info('syslogHost='+syslogHost)

            syslogPort = parser.getint('syslog', 'syslogPort')
            logging.info('syslogPort='+str(syslogPort))

            syslogProto = parser.get('syslog', 'syslogProto')
            logging.info('syslogProto='+syslogProto)

            syslogKeepCSV = parser.getboolean('syslog', 'syslogKeepCSV')
            logging.info('syslogKeepCSV='+str(syslogKeepCSV))

    except Exception as e:
        logging.critical('readConfig('+config+')')
        logging.critical(str(e))
        print('Exception: readConfig('+config+')')
        sys.exit(1)

def changeConfigTime(config,timeStamp,value):
    logging.info('changeConfigTime('+config+','+timeStamp+','+str(value)+')')
    try:
        with open(config, 'r') as f:
            cfgfile = f.read()
            parser = ConfigParser.RawConfigParser(allow_no_value=True)
            # make option names case sensitive
            parser.optionxform = str
            # get config in-memory
            parser.readfp(io.BytesIO(cfgfile))
            # set new timeStamp in request section
            parser.set('request', timeStamp, value)
            # open config file in writ mode
            cfgfile = open(config, 'w')
            # write from in-memory to file
            parser.write(cfgfile)
            cfgfile.close()

    except Exception as e:
        logging.critical('changeConfigTime('+config+','+str(timeStamp)+','+str(value)+')')
        logging.critical(str(e))
        print('Exception: changeConfigTime('+config+','+str(timeStamp)+','+str(value)+')')
        sys.exit(1)

def variableSubstitution(variable):
    global saasCustomerID, saasUserID, saasPath, requestTimestampFrom, startTime, endTime
    newVariable = str(variable)
    newVariable = newVariable.replace("$saasCustomerID$",str(saasCustomerID))
    newVariable = newVariable.replace("$saasUserID$",str(saasUserID))
    newVariable = newVariable.replace('$requestTimestampFrom$',str(startTime))
    newVariable = newVariable.replace('$requestTimestampTo$',str(endTime))

    return newVariable

def syslogForwarder(saasFilename):
    logging.info('Parsing CSV to JSON stream and forwarding to: '+syslogHost+', Port '+str(syslogPort)+' ('+syslogProto+')')
    # create empty in-memory file-like object for JSON transformation
    jsonFile = StringIO.StringIO()
    try:
        # read downloaded CSV and parse it into list
        with open(saasFilename, 'r') as csvFile:
            csvReader = csv.DictReader(csvFile)
            rows = list(csvReader)

        # now for each row in list make corresponding JSON stream and forward via TCP or UDP
        for row in rows:
            message = json.dumps(row, jsonFile)
            if syslogProto == 'TCP':
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.connect((syslogHost, syslogPort))
                sock.send(message)
                sock.close()            
            elif syslogProto == 'UDP':
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.sendto(message, (syslogHost, syslogPort))
        
        if syslogKeepCSV == False:
            logging.info('Clean up: deleting '+saasFilename)
            os.remove(saasFilename)

    except Exception as e:
        logging.critical(str(e))
        sys.exit(1)

# parse config file
readConfig(config)

if not proxyURL:
    logging.info('Using direct connect for request')
else:
    # set proxy servers for request if needed
    requestProxies = {'http': proxyURL, 'https': proxyURL}
    logging.info('Using proxy for request')

# set start for Now - 24 hours if requestTimestampFrom is 0
if requestTimestampFrom == 0:
    requestTimestampFrom = Now-86400

# ready to start making requests
# must make requests in chunked increments
chunkCount = 0
for requestChunk in range(requestTimestampFrom,Now,chunkIncrement):
    chunkCount += 1
    startTime = requestChunk
    endTime = requestChunk+chunkIncrement-1 if requestChunk+chunkIncrement < Now else Now
    
    # change requestTimestampFrom and requestTimestampTo to requestChunk start/stop times
    try:
        requestPath = variableSubstitution(saasPath)
        requestPath = 'https://'+saasHost+requestPath
        requestLogLine = 'requestChunk: '+str(chunkCount)+', '+str(datetime.utcfromtimestamp(startTime))+'('+str(startTime)+') - '+str(datetime.utcfromtimestamp(endTime))+'('+str(endTime)+')'

        if not proxyURL:
            r = requests.get(requestPath, headers=requestHeaders, auth=HTTPBasicAuth(saasUserID, saasPassword), timeout=connectionTimeout)
        else:
            r = requests.get(requestPath, proxies=requestProxies, headers=requestHeaders, auth=HTTPBasicAuth(saasUserID, saasPassword), timeout=connectionTimeout)

        # put response into variable
        output = StringIO.StringIO(r.text.encode('utf-8'))
 
        if r.status_code != 200:
            raise ValueError('Invalid response status: ' + str(r.status_code))

        responseLines = output.read().splitlines()
        # if response is valid but has only 1 line, then it's just a header and should be ignored.    
        if responseLines.__len__() <= 1:
            logging.info(requestLogLine+': no data')

        # first line of response should be fieldHeader
        if responseLines[0] != fieldHeader:
            logging.warning(requestLogLine+': invalid first line: ' + responseLines[0])

        totalLines += responseLines.__len__() - 2
        requestLogLine += ', response: ' + str(r.status_code) + ', responseLines: ' + str(responseLines.__len__()) + ', totalLines: ' + str(totalLines)
        logging.info(requestLogLine)

        # if file does not exist, write the log headers
        saasFilename = saasFilename.replace('$Now$',str(Now))
        if not os.path.isfile(saasFilename):
            logging.info('creating output file: '+saasFilename)
            try:
                with open(saasFilename, 'w+b') as outputFile:
                    outputFile.write(fieldHeader+os.linesep)
            except Exception as e:
                logging.critical("Exception: can't write outputFile: "+saasFilename+': '+str(e))
                sys.exit(1)

        # write the log records
        with open(saasFilename, 'a+b') as outputFile:
        # exclude first line. it's the field headers
            for line in range(1,responseLines.__len__()):
                # exclude any blank lines
                if responseLines[line] == '':
                    continue
                outputFile.write(responseLines[line]+os.linesep)

    except Exception as e:
        logging.critical(str(e))
        sys.exit(1)
    
logging.info('Success: File:'+saasFilename+', From: ' + str(datetime.utcfromtimestamp(startTime)) + '(' + str(startTime) + '), To: ' + str(datetime.utcfromtimestamp(endTime)) + '(' + str(endTime) + '), totalLines: ' + str(totalLines)+', chunkCount: ' + str(chunkCount))

if syslogEnable == True:
    syslogForwarder(saasFilename)

# finally set requestTimestampFrom for next run to current time of execution
changeConfigTime(config,'requestTimestampFrom',Now)
