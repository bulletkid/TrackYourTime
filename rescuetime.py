##from __future__ import print_function
"""Find the currently active window."""

import logging
import sys
import time
import getopt
import codecs
import sys
import signal
import win32gui
import win32process
import win32pdhutil
import wmi
import re

## TODO: Show a menu to user if he has spend 15% time on uncategorized activities/categories
## TODO: Activity calculation should be here - We should be able to run it on demand (NOTE: There is value in both. So keep it here as well as have it separately)
## TODO: Move category and activities to file and load the following 3 arrays from there

category = {"ConEmu": 2, "FireFox": 1, "Outlook": 0 , "Atom": 2, "vim" : 2, "teams" : 1};

## Specific Activities
firefoxActivities = { "Youtube" : -2, "elixir" : 2, "stackoverflow" : 2, "cricinfo" : -2, "primevideo" : -2, "netflix" : -2 }; 

## Not every category need activity specific detail
activityDictionary = {"FireFox": firefoxActivities};

## If you need more granular control of activities, control on per activity basis.
	
def signal_handler(signal, frame): 
    print('You pressed Ctrl+C!') 

    ## Do the calculations here

    print ('** INCOMPLETE SESSION(S) !! ** ')

    sys.exit(0) 



logging.basicConfig(format='%(asctime)s %(levelname)s %(message)s',
                    level=logging.DEBUG,
                    stream=sys.stdout)

def main (argv):
    try:
        opts, args = getopt.getopt(argv, "hs:c:n:",["session=","category=", "number"]) 
    except getopt.GetoptError: 
        print('./rescuetime.py -s <sessionName> -c <category> -n <numSessions>') 
        sys.exit(2)

    print(f"Name of the script      : {sys.argv[0]=}")
    print(f"Arguments of the script : {sys.argv[1:]=}")

    signal.signal(signal.SIGINT, signal_handler) 
    sessionName = "Default"
    category = "Work"
    numSessions = 1
    for opt, arg in opts:
        if opt == "-h":
            print('./rescuetime.py -s <sessionName> -c <category> -n <number>') 
            sys.exit(2)
        elif opt in ("-s", "--session" ):
            sessionName = arg
        elif opt in ("-c", "--category" ):
            category = arg
        elif opt in ("-n", "--number" ):
            numSessions = arg

    ##UTF8Writer = codecs.getwriter('utf8')
    ##sys.stdout = UTF8Writer(sys.stdout)
    
    timeSlept = 0
    timeToSleep = 1
    #timeToSleep = 30
    systemProcesses = dict()

    print( sessionName,category,numSessions )
    while True:

            localtime = time.asctime( time.localtime(time.time()) )
            #print("Active window: %s" % str(localtime get_active_window()))
            #print("Active window: %s" % str(localtime get_active_window()))
            #print( localtime,str(get_active_window()) )
            #activeWindow = get_active_window()
            #activeWindow =  u' '.activeWindow.encode('utf-8').strip()
            activeWindow = str(get_active_window(systemProcesses))


            ## TODO: Add logic for maintaining a session specific count of activities
            ## This follows on the other broader goal of classifying activities as +ve or -ve (or have a weight attached to them)
            ## Will aid in creating a focus score


            ## TODO: This app should also have a taskbar UI equivalent that allows us to easily add session


            #print( localtime, get_active_window() )
            print(( localtime, activeWindow ))
            time.sleep(timeToSleep)

            timeSlept += timeToSleep
            #if timeSlept > 25*60*numSessions :
            if timeSlept > 2*60*numSessions :
                break

    print ('** SESSION(S) COMPLETE!! Many Congrats!!** ')
                
def get_active_window(systemProcesses):
    """
    Get the currently active window.

    Returns
    -------
    string :
        Name of the currently active window.
    """
    import sys
    active_window_name = None
    parent = ""
    windowTitle = None

    if sys.platform in ['linux', 'linux2']:
        # Alternatives: http://unix.stackexchange.com/q/38867/4784
        try:
            import wnck
        except ImportError:
            logging.info("wnck not installed")
            wnck = None
        if wnck is not None:
            screen = wnck.screen_get_default()
            screen.force_update()
            window = screen.get_active_window()
            if window is not None:
                pid = window.get_pid()
                with open("/proc/{pid}/cmdline".format(pid=pid)) as f:
                    active_window_name = f.read()
        else:
            try:
                from gi.repository import Gtk, Wnck
                gi = "Installed"
            except ImportError:
                logging.info("gi.repository not installed")
                gi = None
            if gi is not None:
                Gtk.init([])  # necessary if not using a Gtk.main() loop
                screen = Wnck.Screen.get_default()
                screen.force_update()  # recommended per Wnck documentation
                active_window = screen.get_active_window()
                pid = active_window.get_pid()
                with open("/proc/{pid}/cmdline".format(pid=pid)) as f:
                    active_window_name = f.read()
    elif sys.platform in ['Windows', 'win32', 'cygwin']:
        # http://stackoverflow.com/a/608814/562769
        import win32gui
        window = win32gui.GetForegroundWindow()
        active_window_name = win32gui.GetWindowText(window)

        ## See if we can get the application name too
        ##try:
        ##    parent = win32gui.GetParent(window)
        ##except win32api.error:
        ##    parent = "Unknown"
        ##print( "Parent is " + str(parent))

        ## Get parent
        procs = wmi.WMI().Win32_Process()

        ##pycwnd = win32gui.GetForegroundWindow()
        tid, pid = win32process.GetWindowThreadProcessId(window)

        ## Check process in hashmap
        parent = "Unknown"
        if pid in systemProcesses:
          print ("Found process in dict - Exec is " + systemProcesses[pid] + "\n")
          parent = systemProcesses[pid]
        else:
          #print("Adding process to dict\n")
          for proc in procs:
            if proc.ProcessId == pid:
              print ('pid' + str(pid) )
              print ('exec' + proc.ExecutablePath)
              print ('title'+ win32gui.GetWindowText(window))
              parent = proc.ExecutablePath
              systemProcesses[pid] = parent

        print( "Parent is " + str(parent))


    elif sys.platform in ['Mac', 'darwin', 'os2', 'os2emx']:
        # http://stackoverflow.com/a/373310/562769
        from AppKit import NSWorkspace
        from Quartz import (
                    CGWindowListCopyWindowInfo,
                    kCGWindowListOptionOnScreenOnly,
                    kCGNullWindowID
            )

        active_window_name = (NSWorkspace.sharedWorkspace()
                              .activeApplication()['NSApplicationName'])
        try:
            if sys.platform == "darwin":
                    app = NSWorkspace.sharedWorkspace().frontmostApplication()
                    active_app_name = app.localizedName()
                    #print("Active App(NEW) %s" % str(active_app_name) )
                    #print("Active App(OLD) %s" % str(active_window_name) )

                    options = kCGWindowListOptionOnScreenOnly
                    windowList = CGWindowListCopyWindowInfo(options, kCGNullWindowID)
                    windowTitle = 'Unknown'
                    for window in windowList:

                      windowNumber = window['kCGWindowNumber']
                      ownerName = window['kCGWindowOwnerName']
                      # geometry = window['kCGWindowBounds']
                      windowTitle = window.get('kCGWindowName', 'Unknown')
                      #print("window:title %s" % str(windowTitle) )
                  
                      ##if windowTitle and ( ownerName == active_app_name):
                      if windowTitle and ( ownerName == active_window_name):
                              # logging.debug(
                              #     'ownerName=%s, windowName=%s, x=%s, y=%s, '
                              #     'width=%s, height=%s'
                              #     % (window['kCGWindowOwnerName'],
                              #        window.get('kCGWindowName', u'Unknown'),
                              #        geometry['X'],
                              #        geometry['Y'],
                              #        geometry['Width'],
                              #        geometry['Height']))
                                          #print("app %s" % str(active_window_name ) )
                                          #print(windowTitle )
                        break


            return active_window_name + " : " + windowTitle
    ##                return _review_active_info(active_app_name, windowTitle)
                

        except:
            logging.error('Unexpected error: %s' % sys.exc_info()[0])
            logging.error('error line number: %s' % sys.exc_traceback.tb_lineno)
            return 'Unknown', 'Unknown'

    else:
        print(("sys.platform={platform} is unknown. Please report."
              .format(platform=sys.platform)))
        print((sys.version))

    ## Match the category
    ## TODO: Need to use RE here ; Here is a snippet
    ## if re.search('mandy', 'Mandy Pande', re.IGNORECASE):
    value = 0
    activityCategory = "default"
    for i in set(category.keys()):
      print ("next category is " +i);
      #if (parent.find(i)):
      if (re.search(i, parent, re.IGNORECASE)):
        activityCategory = i
        value = category[i]
        print ("Category is " +i+ " with value " + str(value) )
        break;

    ## Do we have active directory associated with this category?
    if activityCategory in activityDictionary :
      print ("There are more activities associated with category: " +activityCategory);
      ## Checking if this title matches any?
      categoryActivities = activityDictionary[activityCategory]
      for j in set(categoryActivities.keys()):
        print ("next activity is " +j);
        if (re.search(j, active_window_name, re.IGNORECASE)):
          value = categoryActivities[j]
          print ("Activity " + j + " of Category " + activityCategory + " has value " + str(value) )
          break;

    return active_window_name + " : " + parent
    ##+ ":" + str(parent)

if __name__ == "__main__": 
    main(sys.argv[1:])
