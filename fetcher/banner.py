from pystyle import Colors, Colorate

BANNER = """  __  __       _                          ______   _       _               
 |  \/  |     | |                        |  ____| | |     | |              
 | \  / | __ _| |_      ____ _ _ __ ___  | |__ ___| |_ ___| |__   ___ _ __ 
 | |\/| |/ _` | \ \ /\ / / _` | '__/ _ \ |  __/ _ \ __/ __| '_ \ / _ \ '__|
 | |  | | (_| | |\ V  V / (_| | | |  __/ | | |  __/ || (__| | | |  __/ |   
 |_|  |_|\__,_|_| \_/\_/ \__,_|_|  \___| |_|  \___|\__\___|_| |_|\___|_|   
           github.com/SwezyDev    t.me/Swezy    x.com/Swezy_1337
""" # logo art

def show(): # a function to display the banner
    print(Colorate.Horizontal(Colors.red_to_yellow, BANNER)) # print the banner with a red to yellow gradient