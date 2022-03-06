def main():
	import os
	import pyttsx3
	import time

	interface = "wlx00c0caad9873"
	src = "AC:AE:19:DA:34:0B"

	os.system("sudo airmon-ng check kill")
	os.system("sudo airmon-ng start " + interface + " " + "11")
	time.sleep(5)
	os.system("clear")

	language = 'en'

	list = []
	while True:
		list.append(getAverageDbm(interface, src, 50))
		os.system('clear')
		print(list)
		if len(list) > 1:
			if(list[-1] == list[-2]):
				engine = pyttsx3.init()
				engine.say("No Difference " + str(list[-1]))
				print("No Difference")
				engine.runAndWait()
			elif(list[-1] > list[-2]):
				engine = pyttsx3.init()
				engine.say("Getting closer, " + str(list[-1]))
				print("Getting Closer!")
				engine.runAndWait()
			else:
				engine = pyttsx3.init()
				engine.say("Wrong Way, " + str(list[-1]))
				print("Wrong Way!")
				engine.runAndWait()


def getAverageDbm(interface, src, num):
	import numpy
	import subprocess
	import re
	import time
	import pyttsx3

	engine = pyttsx3.init()
	engine.say("move")
	engine.runAndWait()
	time.sleep(2)
	engine.say("Stop")
	engine.runAndWait()
	time.sleep(1)

	outputs= []
	dBms = []
	p = subprocess.Popen(('sudo', 'tcpdump', "-i", interface, "ether", "src", src, '-l'), stdout=subprocess.PIPE)
	print("Capturing!")
	for row in iter(p.stdout.readline, b''):
		try:
			dBms.append(int(re.findall("[-+]?[0-9]?[0-9][d][B][m]", str(row.rstrip()))[0].replace("dBm", "")))
		except:
			print(str(row.rstrip())[0])
		print("Received at", dBms[-1])
		if len(dBms) > num:
			time.sleep(1)
			break

	print(dBms)

	#should round not int
	return int(numpy.median(dBms))

main()
