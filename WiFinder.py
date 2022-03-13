#!/usr/bin/python
# -*- coding: utf-8 -*-
# Author: Github: sonicCrypt0r (https://github.com/sonicCrypt0r)


# Global Imports
from sys import stdout


# Global Variables
VERSION = "1.03"
sprint = stdout.write


def main():
    banner()  # ASCCI Art Banner For Style
    checkLinux()  # Check This Is A Linux Operating System
    checkPriv()  # Check For Root Privleges
    checkDepend()  # Check For Dependencies
    argsDict = parseArgs()  # Parse and Autoset Parameters
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
        exit(1)

    dBmList = []
    while True:
        dBmList.append(getAverageDbmScapy(argsDict, 4))
        adviseUser(dBmList)

    return


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


def checkLinux():
    from platform import system

    os = system()

    if os != "Linux":
        sprint(pStatus("BAD") + "Operating System Is Not Linux Value: " + os + "\n")
        exit(1)

    sprint(pStatus("GOOD") + "Operating System Is Linux Value: " + os)

    return


def clearScr():
    from os import system

    system("clear")

    return


def checkDepend():
    from sys import version_info
    from shutil import which

    if version_info[0] <= 3 and version_info[1] <= 6:
        sprint(
            pStatus("BAD")
            + "This Script Was Designed For Python Version 3.6 or Greater\n"
        )
        exit(1)

    if which("iwconfig") is None:
        sprint(pStatus("BAD") + "Your System Is Missing: iwconfig\n")
        exit(1)

    if which("airmon-ng") is None:
        sprint(pStatus("BAD") + "Your System Is Missing: airmon-ng\n")
        exit(1)

    try:
        import scapy
    except:
        sprint(pStatus("BAD") + "Your System Is Missing Python3 Scapy Module\n")
        exit(1)

    try:
        import pyttsx3
    except:
        sprint(pStatus("BAD") + "Your System Is Missing Python3 pyttsx3 Module\n")
        exit(1)

    sprint(pStatus("GOOD") + "Checking Dependencies Status: Good")

    return


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
        exit(1)

    sprint(pStatus("GOOD") + "This Script Has Root Privledges EUID: " + str(euid))

    return


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


def checkMac(macAddr):
    import re

    if not (
        re.match("[0-9a-f]{2}([-:]?)[0-9a-f]{2}(\\1[0-9a-f]{2}){4}$", macAddr.lower())
    ):
        sprint(pStatus("BAD") + "Invalid Target MAC Address Provided\n")
        exit(1)

    return True


def autoSelectInterface():
    import subprocess
    import os

    sprint(pStatus("GOOD") + "Attempting To Auto Select Interface...")

    ## call date command ##
    DN = open(os.devnull, "w")
    p = subprocess.Popen(("iwconfig"), stdout=subprocess.PIPE, stderr=DN)

    ## Talk with date command i.e. read data from stdout and stderr. Store this info in tuple ##
    ## Interact with process: Send data to stdin. Read data from stdout and stderr, until end-of-file is reached.  ##
    ## Wait for process to terminate. The optional input argument should be a string to be sent to the child process, ##
    ## or None, if no data should be sent to the child.
    (output, err) = p.communicate()

    ## Wait for date to terminate. Get return returncode ##
    procStatus = p.wait()

    potentialInterfaces = []
    i = 0
    if procStatus == 0:
        outputList = output.decode().split("\n")
        while i < len(outputList):
            if "Nickname" in outputList[i]:
                potentialInterfaces.append(outputList[i].split(" ")[0])
            i += 1

    i = 0
    monitorModeInerface = None
    while i < len(potentialInterfaces):
        if startMonMode(potentialInterfaces[i], "None"):
            monitorModeInerface = potentialInterfaces[i]
            break
        i += 1

    if monitorModeInerface == None:
        sprint(pStatus("BAD") + "No Wireless Interfaces Support Monitor Mode\n")
        exit(1)

    return monitorModeInerface


def autoSelectChannel(argsDict):
    from scapy.all import sniff

    twoChannels = [
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

    try:
        while True:
            i = 0
            while i < len(twoChannels):
                startMonMode(argsDict["interface"], twoChannels[i])
                sprint(pStatus("WARN") + "Trying To Auto-Detect Channel")
                a = sniff(iface=argsDict["interface"], timeout=1)
                x = 0
                while x < len(a):
                    try:
                        channelb = twoChannels[i]
                        frequency = a[x].ChannelFrequency
                        channel = a[x].channel
                    except:
                        channel = channelb
                    if str(a[x].addr2).upper() == argsDict["targetMacAddr"]:
                        # sprint("\n" + str(a[x].addr2).upper() + " " + argsDict["targetMacAddr"]+ " " + str(channel) + " " + str(channelb) + " " + str(frequency))
                        # print(a[x].show())
                        raise StopIteration
                    x += 1
                i += 1
    except StopIteration:
        pass

    sprint(pStatus("GOOD") + "Channel Detected " + "Channel: " + str(channel))

    return channel


def pStatus(status):
    # This function is for fancy output throughout the program

    # Colors used for fancy output
    COLORS = {
        "WARN": "\033[93m",
        "GOOD": "\033[92m",
        "BAD": "\033[91m",
        "INPUT": "\033[96m",
        "ENDC": "\033[0m",
        "UP": "\033[F",
    }

    if status == "GOOD":
        return (
            "\n" + COLORS["ENDC"] + "[" + COLORS["GOOD"] + "+" + COLORS["ENDC"] + "] "
        )
    if status == "BAD":
        return "\n" + COLORS["ENDC"] + "[" + COLORS["BAD"] + "+" + COLORS["ENDC"] + "] "
    if status == "WARN":
        return (
            "\n" + COLORS["ENDC"] + "[" + COLORS["WARN"] + "+" + COLORS["ENDC"] + "] "
        )
    if status == "INPUT":
        return (
            "\n" + COLORS["ENDC"] + "[" + COLORS["INPUT"] + "+" + COLORS["ENDC"] + "] "
        )
    if status == "UP":
        return COLORS["UP"]

    return


if __name__ == "__main__":
    main()
