#!/usr/bin/env python

"""Find the currently active window."""

import logging
import sys
import time
import getopt
import codecs
import sys
import signal

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
		print './rescuetime.py -s <sessionName> -c <category> -n <numSessions>' 
		sys.exit(2)

	signal.signal(signal.SIGINT, signal_handler) 
	sessionName = ''
	category = 'Work'
	numSessions = 1
	for opt, arg in opts:
		if opt == "-h":
			print './rescuetime.py -s <sessionName> -c <category> -n <number>' 
			sys.exit(2)
		elif opt in ("-s", "--session" ):
			sessionName = arg
		elif opt in ("-c", "--category" ):
			category = arg
		elif opt in ("-n", "--number" ):
			numSessions = arg

	
	UTF8Writer = codecs.getwriter('utf8')
	sys.stdout = UTF8Writer(sys.stdout)
	
	timeSlept = 0
	timeToSleep = 30

	print ( sessionName, category, numSessions )
	while True:

	    localtime = time.asctime( time.localtime(time.time()) )
	    #print("Active window: %s" % str(localtime get_active_window()))
	    #print("Active window: %s" % str(localtime get_active_window()))
	    #print( localtime,str(get_active_window()) )
	    #activeWindow = get_active_window()
	    #activeWindow =  u' '.activeWindow.encode('utf-8').strip()
	    activeWindow = unicode(get_active_window())


	    ## TODO: Add logic for maintaining a session specific count of activities
	    ## This follows on the other broader goal of classifying activities as +ve or -ve (or have a weight attached to them)
	    ## Will aid in creating a focus score


	    ## TODO: This app should also have a taskbar UI equivalent that allows us to easily add session


	    #print( localtime, get_active_window() )
	    print( localtime, activeWindow )
	    time.sleep(timeToSleep)

	    timeSlept += timeToSleep
	    if timeSlept > 25*60*numSessions :
		    break

	print ('** SESSION(S) COMPLETE!! Many Congrats!!** ')
	    	
def get_active_window():
    """
    Get the currently active window.

    Returns
    -------
    string :
        Name of the currently active window.
    """
    import sys
    active_window_name = None
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
			windowTitle = window.get('kCGWindowName', u'Unknown')
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
        print("sys.platform={platform} is unknown. Please report."
              .format(platform=sys.platform))
        print(sys.version)
    return active_window_name

if __name__ == "__main__": 
	main(sys.argv[1:])
