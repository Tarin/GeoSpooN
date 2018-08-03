#!/usr/bin/python

import requests
import sys
from Tkinter import *
import subprocess
import time
from os import system
from commands import getoutput

mainW = Tk()
mainW.title('GeoSpooN')
# mainW.iconbitmap('GeoSpooN33gif.gif')


def get_iface():  # Select an adapter to use for both Airmon-ng and MDK3
    interfaces = subprocess.check_output(['ipmaddr'])
    faces = interfaces.splitlines()
    wlans = []
    for i in faces:
        if 'wl' in i:
            wlan = i.split(':')
            wlans.append(wlan[1].strip())

    # Create a dropdown menu to choose an Wi-Fi adapter from
    popupmenu = OptionMenu(mainW, wlanvar, *wlans)
    Label(mainW, text="select an interface").grid(row=0, column=2)
    popupmenu.grid(row=1, column=2)

    # Create a dropdown menu to choose the length of time MDK3 will run
    times = [5, 10, 30, 60, 120, 240, 480]
    popupmenu2 = OptionMenu(mainW, timevar, *times)
    Label(mainW, text="select how long to run for (seconds)").grid(row=0, column=3)
    popupmenu2.grid(row=1, column=3)

    b = Button(mainW, text="go", command=start_mon)
    b.grid(row=4, column=3)

'''
def check():  # ensure that all options are set before running
    card = wlanvar.get()
    duration = timevar.get()
    if "wlan" not in card and duration < 5:
        label(mainW, text="Select WLAN and Set Time").grid(row=3, column=3)
    elif "wlan" not in card and duration > 0:
        label(mainW, text="Select a WLAN").grid(row=3, column=3)
    elif "wlan" in card and duration < 5:
        label(mainW, text="Set Time").grid(row=3, column=3)
    elif "wlan" in card and duration > 0:
        start_mon()
'''

def start_mon():
    global airmonon
    card = wlanvar.get()
    cardm = card
    # Try to run Airmon-ng on the selected adapter
    airon = subprocess.call(" airmon-ng" + " start " + cardm, shell=True)

    if airon > 0:  # If Airmon-ng was unsuccessful, try to put it into monitor mode manually
        subprocess.check_output(["ifconfig", card, "down"])
        subprocess.check_output(["iwconfig", card, "mode", "monitor"])
        subprocess.check_output(["ifconfig", card, "up"])
        airmonon = 1
        print "\n************\n" + card + " in monitor mode"
        run_mdk3(card)
    else:
        # print airon
        cardm = card + "mon"
        airmonon = 1
        print "\n************\n" + cardm + " in monitor mode"
        run_mdk3(cardm)


def run_mdk3(cardm):
    global pagenum
    #print pagenum
    duration = timevar.get()
    duration = (duration / pagenum) + 5
    # print str(duration) + ".....split"
    # clean_exit(cardm)
    # sys.exit()
    page = 0
    while pagenum != page:
        print "\nSpoofing page" + str(page)
        mdk = "mdk3 " + cardm + " b -v Data/macsPG" + str(page) + ".txt -g -t"  # Create MDK3 command with the selected adapter/card
        mdk3pop = subprocess.Popen([mdk], shell=True)  # Run MDK3

        page += 1
        time.sleep(duration)
    mdk3on = 1
    clean_exit(cardm, airmonon, mdk3on)


def clean_exit(cardm, airmonon, mdk3on):
    # Kill MDK3 and take adapter out of monitor mode
    if mdk3on == 1:
        for pid in getoutput("ps aux | grep mdk3 | grep -v grep | awk '{print $2}'").splitlines():
            system("kill -9 " + pid)
        print "\n************\nMDK3 Finished"

    if airmonon == 1:
        if "mon" in cardm:  # If Airmon-ng was used to start the adapters monitor mode, use airmon to stop it
            airoff = subprocess.check_output(["airmon-ng", "stop", cardm])  # Runs Airmon-ng STOP on selected card/adapter
            # print airoff
            print "\n************\nMonitor Mode Disabled"

        else:  # If Airmon-ng wasn't used, take the adapter out of monitor mode manually
            subprocess.check_output(["ifconfig", cardm, "down"])
            subprocess.check_output(["iwconfig", cardm, "mode", "managed"])
            subprocess.check_output(["ifconfig", cardm, "up"])
            iwcheck = subprocess.check_output(["iw", cardm, "info"])
            print iwcheck
            print "\n************\nMonitor Mode Disabled"

    subprocess.Popen("rm Data/*.txt", shell=True)  # Remove all unsaved mac files
    print "\n************\nData Files Cleared"


def pages(lat1, lat2, lng1, lng2, nxtpg, wapi1):
    global counter
    #print nxtpg
    page = 1
    cnt = 0
    while str(nxtpg) != 'null':
        # print page
        # if str(nxtpg) != 'null':
        # print nxtpg

        headers2 = {
            'Accept': 'application/json',
            'Authorization': wapi1,
        }

        params2 = (
            ('onlymine', 'false'),
            ('latrange1', lat1),
            ('latrange2', lat2),
            ('longrange1', lng1),
            ('longrange2', lng2),
            ('lastupdt', '20180101'),  # Collect only AP's recorded this year
            ('freenet', 'false'),
            ('paynet', 'false'),
            ('resultsPerPage', '100'),
            ('searchAfter', int(nxtpg))
        )

        result = requests.get('https://api.wigle.net/api/v2/network/search', headers=headers2, params=params2)
        if 'too many queries today' in result.text:
            sys.exit('code 500: Too many queries today')

        txt = result.text
        items = txt.split('{')
        searchaft = items[1].split(',')
        total = searchaft[1].split(':')
        total = int(total[1])
        # print total
        searchaft = searchaft[2].split(':')
        nxtpg = searchaft[1]
        # print nxtpg
        #if str(nxtpg) == 'null':
        #    print "\n\nWINNER WINNER  1\n...................."
        #    return page

        # counter = 0
        ssid = []

        for e in items:

            parts = e.split(',')
            count = 0
            thscount = 0
            sid = ''
            mac = ''
            joint = ''
            for i in parts:
                if 'ssid' in i:
                    clean = i.split('"')
                    clean.reverse()
                    sid = clean[1].strip(' ')
                    count = 1
                elif 'netid' in i:
                    clean = i.split('"')
                    clean.reverse()
                    mac = clean[1]
                    count = 1

            if count > 0:
                joint = mac + ' ' + sid
                ssid.append(joint)
                counter += 1
            count = 0

            #print thscount
            # counter = counter + thscount
        counts.set(str(counter) + " Found")

        if len(ssid) > 0:
            wf = open("Data/macsPG" + str(page) + ".txt", "w")  # Creates a new page for each 100 AP's

            cnt = 0
            for i in ssid:
                wf.write(i)
                wf.write("\n")
                cnt +=1

            # print str(cnt) + " FOUND THIS ROUND"

            wf.close()

        more = nxtpg

        if str(more) != 'null':
            nxtpg = int(more)
            # print "touched 1.. " + str(counter) + "..." + str(page)

        elif str(more) == 'null':
            # print "\n\ntouched 1.. " + str(counter) + "..." + str(page)
            # print "\n\nWINNER WINNER  2\n...................."
            return page

        page = page + 1


def google(gapi1):
    print "**********\nGoogle Is Being Used\n**********"
    global counter
    global pagenum
    g1 = s.get()
    g2 = c.get()
    g3 = u.get()
    addcode = g1 + ", " + g2 + ", " + g3  # format address like: "harmouth road, leeds, UK"

    headers = {
        'Accept': 'application/json',
    }

    params = (
        ('address', addcode),
        ('key', gapi1),
    )

    results = requests.get('https://maps.googleapis.com/maps/api/geocode/json', headers=headers, params=params)

    # print results.text
    # print "\n........................................................................\n"
    if 'too many queries today' in results.text:
        sys.exit('code 500: Too many queries today')

    tstcde = results.text.split('"formatted_address"')
    items = tstcde[1].split('{')
    item = ""
    count = 0
    for i in items:
        if 'location' in i:
            it = count + 1
            item = items[it].split('}')
            break
        else:
            count += 1

    item = item[0].split(',')
    lat = item[0].split(':')
    lat = float(lat[1])
    lng = item[1].split(':')
    lng = float(lng[1])
    latm = lat + 0.001205
    latl = lat - 0.001205

    lngm = lng + 0.001205
    lngl = lng - 0.001205
    goodone = 1
    # print "\n\nGoogle!!\n\n"
    return latl, latm, lngl, lngm, goodone


def addsearch():
    global counter
    global pagenum
    gapi1 = gapi_entry.get()
    wapi1 = wapi_entry.get()
    wapi2 = ""
    lat1 = lat2 = long1 = long2 = None
    goodone = 0
    if gapi1:
        print gapi1
        lat1, lat2, long1, long2, goodone = google(gapi1)  # Try to use google

    # print wapi1
    # goodone = 0

    if goodone != 1:  # If google fails, use WiGLE
        print "**********\nWiGLE Is Being Used\n**********"
        g1 = s.get()
        g2 = c.get()
        g3 = u.get()
        addcode = g1 + ", " + g2 + ", " + g3  # format address like: "middleton road, york, UK"

        if wapi1:
            wapi2 = "Basic " + wapi1

        headers = {
            'Accept': 'application/json',
            'Authorization': wapi2,
        }

        params = (
            ('addresscode', addcode),
        )

        results = requests.get('https://api.wigle.net/api/v2/network/geocode', headers=headers, params=params)
        if 'too many queries today' in results.text:
            sys.exit('code 500: Too many queries today')

        tstcde = results.text

        items = tstcde.split('[')
        bound = items[2].replace(']', '').replace('}', '').split(',')

        lat1 = bound[0]
        lat2 = bound[1]
        long1 = bound[2]
        long2 = bound[3]

    print lat1, lat2, long1, long2

    headers2 = {
        'Accept': 'application/json',
        'Authorization': wapi1
    }

    params2 = (
        ('onlymine', 'false'),
        ('latrange1', lat1),
        ('latrange2', lat2),
        ('longrange1', long1),
        ('longrange2', long2),
        ('lastupdt', '20180101'),  # Collect only AP's recorded this year
        ('freenet', 'false'),
        ('paynet', 'false'),
        ('resultsPerPage', '100'),
    )

    result = requests.get('https://api.wigle.net/api/v2/network/search', headers=headers2, params=params2)
    print "\n*&*&*&*_-_-_-_-_-_-_*&*&*&*\n"
    print result
    if 'too many queries today' in result.text:
        sys.exit('code 500: Too many queries today')

    txt = result.text
    searchaft = txt.split('{')
    searchaft = searchaft[1].split(',')

    totalres = searchaft[1].split(':')
    totalres = int(totalres[1])
    searchaft = searchaft[2].split(':')
    more = searchaft[1]

    counter = 0
    ssid = []
    items = txt.split('{')

    # This next section parses the data retrieved from WiGLE into AP data that MDK3 can use
    for e in items:

        parts = e.split(',')
        count = 0
        sid = ''
        mac = ''
        joint = ''
        for i in parts:
            if 'ssid' in i:
                clean = i.split('"')
                clean.reverse()
                sid = clean[1].strip(' ')
                count = 1
            elif 'netid' in i:
                clean = i.split('"')
                clean.reverse()
                mac = clean[1]
                count = 1

        if count > 0:
            joint = mac + ' ' + sid
            ssid.append(joint)
            counter += 1
        count = 0
    # print counter
    counts.set(str(counter)+" Found")
    wf = open("Data/macsPG0.txt", "w")

    cnt = 0
    for i in ssid:
        wf.write(i)
        wf.write("\n")

    wf.close()
    if totalres > 100:
        # print str(totalres) + "TOTAL"
        pagenum = pages(lat1, lat2, long1, long2, more, wapi1)  # If there are more than 100 AP's, split them into pages of 100

    decide()


def decide():  # Decide if there are enough AP's to proceed or not. Works best with over 50
    if counter > 50:
        print str(counter) + " Addresses Found."
        lbl.set(str(counter) + " Addresses Found")
        get_iface()
    else:
        print str(counter) + " Addresses Found, not enough, try again."
        lbl.set("There weren't enough MAC addresses found, try a different location")


def test():
    global tst
    tst = 1
    lat1 = 53.9472979
    lat2 = 53.9498552
    long1 = -1.1259685
    long2 = -1.1227914
    nxtpg = 200
    # pages(lat1, lat2, long1, long2, nxtpg)
    # subprocess.Popen("rm Data/*.txt", shell=True)


# global variables
mdk3on = 0
airmonon = 0
cardm = "undefined"


pagenum = 1  # Set to one to make sure the MDK3 command is run if there is only one page of AP's
counter = 0


lbl = StringVar()
lbl.set('')
Label(mainW, textvariable=lbl).grid(row=4, column=2)

# Create GUI Global Variables
label = StringVar()
wlanvar = StringVar()
timevar = IntVar()
s = StringVar()
c = StringVar()
u = StringVar()
counts = StringVar()
google_api = StringVar()
wigle_api = StringVar()

# Create text input boxes for the GUI
gapi_entry = Entry(mainW, textvariable=google_api)
wapi_entry = Entry(mainW, textvariable=wigle_api)
s_entry = Entry(mainW, textvariable=s)
c_entry = Entry(mainW, textvariable=c)
u_entry = Entry(mainW, textvariable=u)

gapi = Label(mainW, text="Google API Key (optional)")
wapi = Label(mainW, text="WiGLE API Key (required)")
street = Label(mainW, text="Street Name")
city = Label(mainW, text="City")
country = Label(mainW, text="Country")

# Place Labels into the GUI window using grid
gapi.grid(row=0, column=0, sticky=E)
wapi.grid(row=1, column=0, sticky=E)
street.grid(row=2, column=0, sticky=E)
city.grid(row=3, column=0, sticky=E)
country.grid(row=4, column=0, sticky=E)

# Place Entries into the GUI window using grid
gapi_entry.grid(row=0, column=1)
wapi_entry.grid(row=1, column=1)
s_entry.grid(row=2, column=1)
c_entry.grid(row=3, column=1)
u_entry.grid(row=4, column=1)


b = Button(mainW, text="Get Macs From Address", command=addsearch)
b.grid(row=5, column=0, columnspan=2)
t = Button(mainW, text="TEST", command=test)
t.grid(row=6, column=0)

# clExit = Button(mainW, text='Clean exit', command=clean_exit(cardm, airmonon, mdk3on))
# clExit.grid(row=4, column=4)

mainW.mainloop()  # Keeps the GUI running
