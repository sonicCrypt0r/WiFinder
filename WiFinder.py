#!/usr/bin/python
# -*- coding: utf-8 -*-
# Author: Github: sonicCrypt0r (https://github.com/sonicCrypt0r)
# Description: This Script Helps You Physically Find A Device From MAC Address.


# Global Imports
from sys import stdout


# Global Variables
VERSION = "1.04"
sprint = stdout.write


# Establishes General Flow Of The Program.
def main():
    banner()  # Prints ASCCI Art Banner For Style
    checkLinux()  # Check This Is A Linux Operating System
    checkPriv()  # Check For Root Privleges
    checkDepend()  # Check For Dependencies
    argsDict = parseArgs()  # Parse and Autoset Parameters

    # Attempt To Start Monitor Mode Quit If Failed
    if (
        startMonMode(argsDict["interface"], argsDict["channel"]) == False
    ):  # Start Monitor Mode On Interface
        sprint(
            pStatus("BAD")
            + "Starting Monitor Mode Failed Interface: "
            + argsDict["interface"]
            + ", Channel: "
            + str(argsDict["channel"] + "\n")
        )
        exit(1)  # Exit With Error Code

    # Empty List That Will Hold The Average dBm From Each Sniffing Session
    dBmList = []
    try:
        while True:
            dBmList.append(
                getAverageDbmScapy(argsDict, 4)
            )  # Sniff Packets For 4 Seconds Append Median dBm To List
            # Based On New dBm Median Advise User On If They Are Going The Right Way
            adviseUser(dBmList)
    except KeyboardInterrupt:
        stopMonMode(argsDict["interface"])

    return


# This Function Takes An Interface Out Of Monitor Mode.
def stopMonMode(interface):
    from os import system

    sprint(pStatus("GOOD") + "Stopping Monitor Mode On Interface: " + interface)

    cmd = "sudo airmon-ng stop " + interface + " >/dev/null 2>&1"
    system(command)

    sprint(pStatus("GOOD") + "Monitor Mode Stopped On Interface: " + interface)

    return


# This Funcion Sniffs For time Frames From Target MAC Addr Returns Median Of dBms.
def getAverageDbmScapy(argsDict, time):
    from scapy.all import sniff
    from numpy import median
    import pyttsx3
    from time import sleep

    engine = pyttsx3.init()

    engine.say("Move!")
    sprint(pStatus("GOOD") + "Move!")
    engine.runAndWait()
    sleep(3)

    engine.say("Stop!")
    sprint(pStatus("GOOD") + "Stop!")
    engine.runAndWait()
    sleep(1)

    sprint(pStatus("GOOD") + "Starting To Sniff...")

    a = sniff(iface=argsDict["interface"], timeout=time)

    x = 0
    dBmList = []
    while x < len(a):
        if str(a[x].addr2).upper() == argsDict["targetMacAddr"]:
            if (isinstance(a[x].dBm_AntSignal, int)) or (
                isinstance(a[x].dBm_AntSignal, float)
            ):
                dBmList.append(a[x].dBm_AntSignal)
        x += 1

    if len(dBmList) < 1:
        sprint(pStatus("BAD") + "Not Enough Readings ")
        return -999999
    else:
        sprint(pStatus("GOOD") + "Got " + str(len(dBmList)) + " Readings")

    return int(round(median(dBmList)))


# This Function Checks If On Linux Terminates If Not.
def checkLinux():
    from platform import system

    os = system()

    if os != "Linux":
        sprint(pStatus("BAD") + "Operating System Is Not Linux Value: " + os + "\n")
        exit(1)  # Exit With Error Code

    sprint(pStatus("GOOD") + "Operating System Is Linux Value: " + os)

    return


# This Function Checks Dependencies Terminates If Not Found.
def checkDepend():
    from sys import version_info
    from shutil import which

    if version_info[0] <= 3 and version_info[1] <= 6:
        sprint(
            pStatus("BAD")
            + "This Script Was Designed For Python Version 3.6 or Greater\n"
        )
        exit(1)  # Exit With Error Code

    if which("iwconfig") is None:
        sprint(pStatus("BAD") + "Your System Is Missing: iwconfig\n")
        exit(1)  # Exit With Error Code

    if which("airmon-ng") is None:
        sprint(pStatus("BAD") + "Your System Is Missing: airmon-ng\n")
        exit(1)  # Exit With Error Code

    try:
        import scapy
    except:
        sprint(pStatus("BAD") + "Your System Is Missing Python3 Scapy Module\n")
        exit(1)  # Exit With Error Code

    try:
        import pyttsx3
    except:
        sprint(pStatus("BAD") + "Your System Is Missing Python3 pyttsx3 Module\n")
        exit(1)  # Exit With Error Code

    sprint(pStatus("GOOD") + "Checking Dependencies Status: Good")

    return


# This Function Prints ASCCI Art Banner For Style
def banner():
    banner = r"""                                                                           
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
					VERSION: {VERSION}
					BY: sonicCrypt0r"""
    print(banner.replace("{VERSION}", VERSION))

    return


# This Function Takes A Tuple Of Median dBms Advises User If They Are Getting Closer.
def adviseUser(listDb):
    import pyttsx3

    engine = pyttsx3.init()
    if len(listDb) > 1:
        dBmDiff = listDb[-1] - listDb[-2]
        if listDb[-1] == -999999:
            engine.say("No Readings!")
            sprint(
                pStatus("WARN")
                + "No Readings! dBm:"
                + str(listDb[-1])
                + ", Difference:"
                + str(dBmDiff)
                + ", Latest Readings: "
                + str(listDb[-5:])
            )
            engine.runAndWait()
        elif dBmDiff > 1:
            engine.say("Getting closer, " + str(listDb[-1]))
            sprint(
                pStatus("GOOD")
                + "Getting Closer! dBm:"
                + str(listDb[-1])
                + ", Difference:"
                + str(dBmDiff)
                + ", Latest Readings: "
                + str(listDb[-5:])
            )
            engine.runAndWait()
        elif dBmDiff < -1:
            engine.say("Wrong Way, " + str(listDb[-1]))
            sprint(
                pStatus("BAD")
                + "Wrong Way! dBm:"
                + str(listDb[-1])
                + ", Difference:"
                + str(dBmDiff)
                + ", Latest Readings: "
                + str(listDb[-5:])
            )
            engine.runAndWait()
        else:
            engine.say("No Difference " + str(listDb[-1]))
            sprint(
                pStatus("WARN")
                + "No Difference! dBm:"
                + str(listDb[-1])
                + ", Difference:"
                + str(dBmDiff)
                + ", Latest Readings: "
                + str(listDb[-5:])
            )
            engine.runAndWait()

    return


# This Function Checks For Root Privledges Terminates If Not Root.
def checkPriv():
    from os import geteuid

    euid = geteuid()

    if euid != 0:
        sprint(
            pStatus("BAD")
            + "This Script Does Not Have Root Privledges EUID: "
            + str(euid)
            + "\n"
        )
        exit(1)  # Exit With Error Code

    sprint(pStatus("GOOD") + "This Script Has Root Privledges EUID: " + str(euid))

    return


# This Function Starts Monitor Mode On An Interface And Checks The Interface After.
def startMonMode(interface, channel):
    # Needs Way To Check If Monitor Mode Was Successful
    from os import system
    import os
    from time import sleep
    import subprocess

    sprint(pStatus("GOOD") + "Killing Network Manager Service...")

    try:
        system("sudo airmon-ng check kill >/dev/null 2>&1")
    except:
        sprint("Killing Network Manager Service:FAILED")

    sprint(
        pStatus("GOOD")
        + "Starting Monitor Mode On Interface: "
        + interface
        + ", Channel: "
        + str(channel)
    )

    if channel == "None":
        command = "sudo airmon-ng start " + interface + " >/dev/null 2>&1"
    else:
        command = (
            "sudo airmon-ng start "
            + interface
            + " "
            + str(channel)
            + " >/dev/null 2>&1"
        )

    try:
        system(command)
    except:
        sprint("Enabling Monitor Mode On Interface: " + interface + " FAILED")

    sprint(
        pStatus("GOOD")
        + "Checking If Interface Is In Monitor Mode Interface:"
        + interface
    )
    ## call date command ##
    DN = open(os.devnull, "w")
    p = subprocess.Popen(("iwconfig"), stdout=subprocess.PIPE, stderr=DN)
    (output, err) = p.communicate()
    procStatus = p.wait()

    i = 0
    if procStatus == 0:
        outputList = output.decode().split("\n")
        while i < len(outputList):
            if interface in outputList[i]:
                interfaceMode = str(
                    outputList[i + 1].split("Mode:")[1].split("Freq")[0]
                ).strip()
                if interfaceMode == "Monitor":
                    sprint(
                        pStatus("GOOD")
                        + "Interface Is In Monitor Mode Interface: "
                        + interface
                        + ", Channel: "
                        + str(channel)
                    )
                    return True
                else:
                    pass
                    sprint(
                        pStatus("BAD")
                        + "Failed To Put Interface In Monitor Mode Interface: "
                        + interface
                    )
            i += 1

    return False


# This Function Parses The Arguments Given At The CLI
def parseArgs():
    import argparse

    argsDict = {
        "interface": None,
        "targetMacAddr": None,
        "channel": None,
    }

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-i", "--interface", help="\nWireless Interface (With Monitor Mode)"
    )
    parser.add_argument(
        "-t", "--target", help="Target Devices's MAC Address", required=True
    )
    parser.add_argument("-c", "--channel", help="Wireless Channel Of Target Device")
    parser.add_argument(
        "-v",
        "--version",
        action="version",
        version="Version: " + VERSION,
        help="Show Version Number",
    )

    # Read arguments from command line
    sprint("\n\n")
    args = parser.parse_args()
    sprint(pStatus("UP") + pStatus("UP"))

    if args.interface == None:
        argsDict["interface"] = autoSelectInterface()
    else:
        argsDict["interface"] = args.interface

    if checkMac(args.target):
        argsDict["targetMacAddr"] = args.target.upper()

    if args.channel == None:
        argsDict["channel"] = autoSelectChannel(argsDict)
    else:
        argsDict["channel"] = args.channel

    return argsDict


# This Function Checks If A MAC Address Is Valid If Not Terminate.
def checkMac(macAddr):
    import re

    if not (
        re.match("[0-9a-f]{2}([-:]?)[0-9a-f]{2}(\\1[0-9a-f]{2}){4}$", macAddr.lower())
    ):
        sprint(pStatus("BAD") + "Invalid Target MAC Address Provided\n")
        exit(1)  # Exit With Error Code

    return True


# This Function Attempts To Find An Interface Capable Of Monitor Mode.
def autoSelectInterface():
    import subprocess
    from os import devnull

    sprint(pStatus("GOOD") + "Attempting To Auto Select Interface...")

    # Execute "iwconfig" with no output & Wait For Command To Finish
    DN = open(devnull, "w")
    p = subprocess.Popen(("iwconfig"), stdout=subprocess.PIPE, stderr=DN)
    (output, err) = p.communicate()
    procStatus = p.wait()

    # Empty Tuple That Will Hold All Interfaces
    potentialInterfaces = []
    i = 0
    if procStatus == 0:
        outputList = output.decode().split("\n")
        while i < len(outputList):
            if "Nickname" in outputList[i]:
                # Append Interface To Potential Interfaces Tuple
                potentialInterfaces.append(outputList[i].split(" ")[0])
            i += 1

    # Try To Put Every Device From Potential Interfaces Tuple In Monitor Mode Stop On First Success
    i = 0
    monitorModeInerface = None
    while i < len(potentialInterfaces):
        if startMonMode(potentialInterfaces[i], "None"):
            monitorModeInerface = potentialInterfaces[i]
            break
        i += 1

    # If No Intefaces Supported Monitor Mode
    if monitorModeInerface == None:
        sprint(pStatus("BAD") + "No Wireless Interfaces Support Monitor Mode\n")
        exit(1)  # Exit With Error Code

    # Monitor Mode Interface
    return monitorModeInerface


# This Function Attempts To Auto Detect Which Channel A Target Device Is On.
def autoSelectChannel(argsDict):
    from scapy.all import sniff

    # List Of All Possible Channels (Should Overlapping Channels Be Here? Seems Like No)
    allChannelsList = [
        1,
        6,
        11,
        36,
        40,
        44,
        48,
        52,
        60,
        64,
        100,
        104,
        108,
        112,
        116,
        120,
        124,
        128,
        132,
        136,
        140,
        144,
        149,
        153,
        157,
        161,
        165,
    ]

    channelFinal = None
    while channelFinal == None:
        i = 0
        while i < len(allChannelsList) and channelFinal == None:
            startMonMode(argsDict["interface"], allChannelsList[i])
            sprint(pStatus("WARN") + "Trying To Auto-Detect Channel")
            a = sniff(iface=argsDict["interface"], timeout=1)
            x = 0
            while x < len(a):
                # If Packet Was From The Target MAC Address
                if str(a[x].addr2).upper() == argsDict["targetMacAddr"]:
                    channelRecvdOn = allChannelsList[
                        i
                    ]  # Channel You Were Listening On When You Received The Packet
                    try:
                        # This May Cause Exception For Some Reason Sometimes Scapy 802.11 Radio Dummy Header Channel Is Empty
                        channelFrmHeadr = a[
                            x
                        ].channel  # Channel In the 802.11 Radio Dummy Header
                        channelFinal = channelFrmHeadr  # Channel That Will Be Returned From This Function
                        # frequency = a[x].ChannelFrequency # This May Be Useful At Somepoint
                    except:
                        # If No channelFrmHeadr Use channelRecvdOn
                        channelFinal = channelRecvdOn
                    finally:
                        break  # Break Out Of The Entire Block
                x += 1
            i += 1

    sprint(pStatus("GOOD") + "Channel Detected " + "Channel: " + str(channelFinal))

    return channelFinal


# This Function Is For Fancy Output Throughout The Program
def pStatus(status):
    # Colors Used For Fancy Output
    COLORS = {
        "WARN": "\033[93m",  # Yellow
        "GOOD": "\033[92m",  # Green
        "BAD": "\033[91m",  # Red
        "INPUT": "\033[96m",  # Blue
        "ENDC": "\033[0m",  # White
        "UP": "\033[F",  # This Goes Up A Line
    }

    # Select Color/Prefix Based On "status"
    if status == "GOOD":
        prefix = (
            "\n" + COLORS["ENDC"] + "[" + COLORS["GOOD"] + "+" + COLORS["ENDC"] + "] "
        )
    elif status == "BAD":
        prefix = (
            "\n" + COLORS["ENDC"] + "[" + COLORS["BAD"] + "+" + COLORS["ENDC"] + "] "
        )
    elif status == "WARN":
        prefix = (
            "\n" + COLORS["ENDC"] + "[" + COLORS["WARN"] + "+" + COLORS["ENDC"] + "] "
        )
    elif status == "INPUT":
        prefix = (
            "\n" + COLORS["ENDC"] + "[" + COLORS["INPUT"] + "+" + COLORS["ENDC"] + "] "
        )
    elif status == "UP":
        prefix = COLORS["UP"]

    return prefix


# This Calls The Main Function.
if __name__ == "__main__":
    main()
