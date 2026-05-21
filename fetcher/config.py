from .formatter import get_time
from colorama import Fore
import json
import sys
import os

CONFIG_FILE = "config.json" # config filename

TEMPLATE = { # template for default config
	"triage": { # tria.ge settings
		"api_key": "", # your tria.ge api key (get from https://tria.ge/account - YOU NEED RESEARCH ACCESS TO GET AN API KEY)
		"malware_family": [], # list of malware families to track (e.g. ["redline", "asyncrat", "xworm"])
		"malware_tags": [], # list of tags to filter (e.g. ["stealer", "persistence", "keylogger"])
		"poll_interval": 30, # seconds between polls (default 30s - RECOMMENDED)
		"max_results": 50 # max samples per poll (default 50 - RECOMMENDED)
	},
	"telegram": { # telegram bot settings
		"bot_token": "", # your telegram bot token (get from https://t.me/BotFather)
		"chat_id": "", # your telegram user id (leave empty to skip DM notifications)
		"group_id": "", # telegram group chat id (leave empty to skip group notifications)
		"topic_id": "" # telegram topic id for forum groups (leave empty for general channel)
	}
}

def load(): # function to load the config file
	if not os.path.exists(CONFIG_FILE): # if config doesnt exist
		with open(CONFIG_FILE, "w") as f: # create and open the file
			json.dump(TEMPLATE, f, indent=4) # write the template to file
		print(f"\n{Fore.RESET}{get_time()}{Fore.LIGHTBLACK_EX} | {Fore.RESET}[{Fore.YELLOW}INFO{Fore.RESET}] Created {Fore.YELLOW}{CONFIG_FILE}{Fore.RESET} {Fore.LIGHTBLACK_EX}|{Fore.RESET} Fill in your API keys, then re-run.{Fore.RESET}") # print message
		sys.exit(0) # exit the program

	with open(CONFIG_FILE, "r") as f: # open config file
		return json.load(f) # return parsed JSON config
