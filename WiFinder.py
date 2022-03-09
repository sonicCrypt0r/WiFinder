#!/usr/bin/python
# -*- coding: utf-8 -*-
# Author: Github: sonicCrypt0r (https://github.com/sonicCrypt0r)


#Global Imports
from sys import stdout
sprint = stdout.write


def main():
	banner()  # ASCCI Art Banner For Style
	checkLinux()  # Check This Is A Linux Operating System
	checkPriv()  # Check For Root Privleges
	argsDict = parseArgs()  # Parse and Autoset Parameters
	startMonMode(argsDict["interface"], argsDict["channel"])  # Start Monitor Mode On Interface'''

	dBmList = []
	while True:
		dBmList.append(getAverageDbm(argsDict, 50))
		adviseUser(dBmList)

	return

def checkLinux():
	from platform import system

	os = system()

	if os != "Linux":
		sprint(pStatus("BAD") + "Operating System Is Not Linux Value: " + os)
		exit(1)
	
	sprint(pStatus("GOOD") + "Operating System Is Linux Value: " + os)
	
	return

def clearScr():
	from os import system

	system("clear")

	return


def banner():
	print(r"""                                                                           
@@@  @@@  @@@  @@@  @@@@@@@@  @@@  @@@  @@@  @@@@@@@   @@@@@@@@  @@@@@@@   
@@@  @@@  @@@  @@@  @@@@@@@@  @@@  @@@@ @@@  @@@@@@@@  @@@@@@@@  @@@@@@@@  
@@!  @@!  @@!  @@!  @@!       @@!  @@!@!@@@  @@!  @@@  @@!       @@!  @@@  
!@!  !@!  !@!  !@!  !@!       !@!  !@!!@!@!  !@!  @!@  !@!       !@!  @!@  
@!!  !!@  @!@  !!@  @!!!:!    !!@  @!@ !!@!  @!@  !@!  @!!!:!    @!@!!@!   
!@!  !!!  !@!  !!!  !!!!!:    !!!  !@!  !!!  !@!  !!!  !!!!!:    !!@!@!    
!!:  !!:  !!:  !!:  !!:       !!:  !!:  !!!  !!:  !!!  !!:       !!: :!!   
:!:  :!:  :!:  :!:  :!:       :!:  :!:  !:!  :!:  !:!  :!:       :!:  !:!  
 :::: :: :::    ::   ::        ::   ::   ::   :::: ::   :: ::::  ::   :::  
  :: :  : :    :     :        :    ::    :   :: :  :   : :: ::    :   : :  
					BY: sonicCrypt0r""")


def adviseUser(listDb):
	import pyttsx3

	engine = pyttsx3.init()
	if len(listDb) > 1:
		dBmDiff = listDb[-1] - listDb[-2]
		if dBmDiff == 0:
			engine.say("No Difference " + str(listDb[-1]))
			sprint(pStatus("WARN") + "No Difference! dBm:" + str(listDb[-1]) + ", Difference:" + str(dBmDiff))
			engine.runAndWait()
		elif dBmDiff > 1:
			engine.say("Getting closer, " + str(listDb[-1]))
			sprint(pStatus("GOOD") + "Getting Closer! dBm:" + str(listDb[-1]) + ", Difference:" + str(dBmDiff))
			engine.runAndWait()
		elif dBmDiff < -1:
			engine.say("Wrong Way, " + str(listDb[-1]))
			sprint(pStatus("BAD") + "Wrong Way! dBm:" + str(listDb[-1]) + ", Difference:" + str(dBmDiff))
			engine.runAndWait()

	return


def checkPriv():
	from os import geteuid

	euid = geteuid()

	if euid != 0:
		sprint(pStatus("BAD") + "This Script Does Not Have Root Privledges EUID: " + str(euid))
		exit(1)

	sprint(pStatus("GOOD") + "This Script Has Root Privledges EUID: " + str(euid))

	return


def startMonMode(interface, channel):
	# Needs Way To Check If Monitor Mode Was Successful
	from os import system
	import os
	from time import sleep
	import subprocess
	
	#sprint(pStatus("GOOD") + "Killing Network Manager Service...")
	
	try:
		system("sudo airmon-ng check kill >/dev/null 2>&1")
	except:
		sprint("Killing Network Manager Service:FAILED")

	#sprint(pStatus("GOOD") + "Starting Monitor Mode On Interface:" + interface + ", Channel:" + str(channel))
	
	try:
		system(
			"sudo airmon-ng start "
			+ interface
			+ " "
			+ str(channel) + " >/dev/null 2>&1"
		)
	except:
		sprint("Enabling Monitor Mode On Interface: " + interface + " FAILED")

	#sprint(pStatus("GOOD") + "Checking If Interface Is In Monitor Mode Interface:" + interface)
	## call date command ##
	DN = open(os.devnull, 'w')
	p = subprocess.Popen(("iwconfig"), stdout=subprocess.PIPE, stderr=DN)
	(output, err) = p.communicate()
	pStatus = p.wait()


	i = 0
	if pStatus == 0:
		outputList = output.decode().split("\n")
		while i < len(outputList):
			if interface in outputList[i]:
				interfaceMode = str(outputList[i+1].split("Mode:")[1].split("Freq")[0]).strip()
				if interfaceMode == "Monitor":
					sprint("\nInterface Is In Monitor Mode Interface: " + interface + ", Channel:" + str(channel))
					return True
				else:
					pass
					sprint("\nFailed To Put Interface In Monitor Mode Interface: " + interface)
			i += 1

	return False


def parseArgs():
	import argparse

	argsDict = {
		"interface": None,
		"targetMacAddr": None,
		"channel": None,
		"language": "en",
	}

	parser = argparse.ArgumentParser()
	parser.add_argument(
		"-i", "--interface", help="\nWireless Interface (With Monitor Mode)"
	)
	parser.add_argument(
		"-t", "--target", help="Target Devices's MAC Address", required=True
	)
	parser.add_argument("-c", "--channel", help="Wireless Channel Of Target Device")
	parser.add_argument("-l", "--language", help="Language Ex: en")

	# Read arguments from command line
	sprint("\n\n")
	args = parser.parse_args()
	sprint(pStatus("UP") + pStatus("UP"))

	if args.interface == None:
		argsDict["interface"] = autoSelectInterface()
	else:
		argsDict["interface"] = args.interface

	if args.channel == None:
		argsDict["channel"] = autoSelectChannel(argsDict)

	if checkMac(args.target):
		argsDict["targetMacAddr"] = args.target

	return argsDict


def checkMac(macAddr):
	import re

	if re.match("[0-9a-f]{2}([-:]?)[0-9a-f]{2}(\\1[0-9a-f]{2}){4}$", macAddr.lower()):
		return True
	else:
		return False


def autoSelectInterface():
	import subprocess
	import os

	#sprint(pStatus("GOOD") + "Attempting To Auto Select Interface...")

	## call date command ##
	DN = open(os.devnull, 'w')
	p = subprocess.Popen(("iwconfig"), stdout=subprocess.PIPE, stderr=DN)
	
	## Talk with date command i.e. read data from stdout and stderr. Store this info in tuple ##
	## Interact with process: Send data to stdin. Read data from stdout and stderr, until end-of-file is reached.  ##
	## Wait for process to terminate. The optional input argument should be a string to be sent to the child process, ##
	## or None, if no data should be sent to the child.
	(output, err) = p.communicate()
	
	## Wait for date to terminate. Get return returncode ##
	pStatus = p.wait()

	potentialInterfaces = []
	i = 0
	if pStatus == 0:
		outputList = output.decode().split("\n")
		while i < len(outputList):
			if "Nickname" in outputList[i]:
				potentialInterfaces.append(outputList[i].split(" ")[0])
			i += 1

	i = 0
	monitorModeInerface = None
	while i < len(potentialInterfaces):
		if startMonMode(potentialInterfaces[i], 6):
			monitorModeInerface = potentialInterfaces[i]
			break
		i += 1
	
	if monitorModeInerface == None:
		#sprint(pStatus("BAD") + "No Wireless Interfaces Support Monitor Mode")
		exit(1)

	return monitorModeInerface


def autoSelectChannel(argsDict):
	channel = 11
	sprint(pStatus("WARN") + "This Does Nothing Yet (Setting To 11)")
	return channel


def getAverageDbm(argsDict, num):
	import numpy
	import subprocess
	import re
	import time
	import pyttsx3
	import os

	interface = argsDict["interface"]
	src = argsDict["targetMacAddr"]

	engine = pyttsx3.init()
	engine.say("Move!")
	sprint(pStatus("GOOD") + "Move!")
	engine.runAndWait()
	time.sleep(3)
	engine.say("Stop!")
	sprint(pStatus("GOOD") + "Stop!")
	engine.runAndWait()
	time.sleep(1)
	
	sprint(pStatus("GOOD") + "Starting To Sniff...")

	outputs= []
	dBms = []
	DN = open(os.devnull, 'w')
	p = subprocess.Popen(('sudo', 'tcpdump', "-i", interface, "ether", "src", src, '-l'), stdout=subprocess.PIPE, stderr=DN)
	for row in iter(p.stdout.readline, b''):
		try:
			dBms.append(int(re.findall("[-+]?[0-9]?[0-9][d][B][m]", str(row.rstrip()))[0].replace("dBm", "")))
		except:
			print(str(row.rstrip())[0])
		#For Diag
		#print("Received at", dBms[-1])
		if len(dBms) > num:
			time.sleep(1)
			break
	#For Diag
	#print(dBms)

	#should round not int
	return int(numpy.median(dBms))


def pStatus(status):
	#This function is for fancy output throughout the program

	# Colors used for fancy output
	COLORS = {
		'WARN': '\033[93m',
		'GOOD': '\033[92m',
		'BAD': '\033[91m',
		'INPUT': '\033[96m',
		'ENDC': '\033[0m',
		'UP': '\033[F',
		}

	if status == 'GOOD':
		return '\n' + COLORS['ENDC'] + '[' + COLORS['GOOD'] + '+' \
			+ COLORS['ENDC'] + '] '
	if status == 'BAD':
		return '\n' + COLORS['ENDC'] + '[' + COLORS['BAD'] + '+' \
			+ COLORS['ENDC'] + '] '
	if status == 'WARN':
		return '\n' + COLORS['ENDC'] + '[' + COLORS['WARN'] + '+' \
			+ COLORS['ENDC'] + '] '
	if status == 'INPUT':
		return '\n' + COLORS['ENDC'] + '[' + COLORS['INPUT'] + '+' \
			+ COLORS['ENDC'] + '] '
	if status == 'UP':
		return COLORS['UP']

	return


if __name__ == "__main__":
	main()
