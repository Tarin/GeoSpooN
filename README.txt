# GeoSpooN
A Geo-location Spoofed Network program

This program is in the early stages of development and was initially built as a means to test the weakness of Wi-Fi Positioning Systems.

The program makes use of both Google and WiGLE to spoof the MAC address and SSID's of however many network routers it can gather from a specific location which is input by the user.

In order to use this program a user must obtain a WiGLE API key from Wigle.net (must be the 'Encoded for use' API key) and an optional Google maps API key (for added accuracy).


It runs only on Linux for the moment and requires ifconfig, ip, iwconfig, iw, Aircrack-ng and MDK3 to operate effectively. The use of a decent external Wi-Fi adapter increases effectiveness a lot!

I am working on making it available as a command line tool also, to be able to run it from the raspberry pi, making it a lot more portable.

NOTE!!: THIS IS FOR RESEARCH USE ONLY, IF USED IMPROPERLY IT CAN HAVE AN EFFECT ON OTHER DEVICES WITHIN RANGE, PLEASE USE RESPONSIBLY.
