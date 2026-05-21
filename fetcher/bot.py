from .telegram import send_telegram
from .formatter import get_time
from colorama import Fore
import requests
import pyzipper
import json
import os

API = "https://api.telegram.org/bot{token}" # tg api

def get_updates(token, offset=None): # function to get updates from telegram
	url = f"{API}/getUpdates".format(token=token) # build getUpdates url
	payload = {"timeout": 30} # set long polling timeout
	if offset: # if offset provided, add to payload to get next updates
		payload["offset"] = offset # offset already incremented by caller
	try: # try to get updates
		req = requests.post(url, data=payload) # make POST request to getUpdates endpoint
		if req.ok: # if request successful, return json response
			return req.json() # return updates data
		return None # return none on failure
	except Exception as e: # if request fails, print error and return none
		return None # return none on error
	
def hash_to_exe(hash_input, reports_dir="reports"): # function to find .malware file by hash or folder name
	hash_input = hash_input.lower().strip() # normalize input

	if not os.path.exists(reports_dir): # if reports directory doesnt exist, return none
		return None # return none if reports dir doesnt exist

	for fam in os.listdir(reports_dir): # iterate through malware family folders
		fam_path = os.path.join(reports_dir, fam) # build family path
		if not os.path.isdir(fam_path): # if not a directory, skip
			continue # skip non directory files

		for folders in os.listdir(fam_path): # iterate through folders in family
			folder_p = os.path.join(fam_path, folders) # build folder path
			if not os.path.isdir(folder_p): # if not a directory, skip
				continue # skip non directory files

			if folders.lower() == hash_input: # if folder name matches input hash, look for .malware file inside
				for file in os.listdir(folder_p): # iterate through files in folder
					if file.endswith(".malware"): # if file ends with .malware, return its path
						return os.path.join(folder_p, file) # return path to .malware file

			config_path = os.path.join(folder_p, "config.json") # path to config file that contains hashes
			if os.path.exists(config_path): # if config file exists, check if it contains the hash
				try: # try to read config and compare hashes
					with open(config_path, "r") as f: # open config file for reading
						cfg = json.load(f) # load config json
						md5 = cfg.get("md5", "").lower() # get md5 hash from config and normalize
						sha256 = cfg.get("sha256", "").lower() # get sha256 hash from config and normalize

						if md5 == hash_input or sha256 == hash_input: # if either hash matches input, look for .malware file in the same folder
							for file in os.listdir(folder_p): # iterate through files in folder
								if file.endswith(".malware"): # if file ends with .malware, return its path
									return os.path.join(folder_p, file) # return path to .malware file
				except Exception as e: # if any error occurs (e.g. invalid json), print and skip
					continue # skip to next folder

	return None # return none if no matching file found

def decode_malware(malware_path): # function to decode the .malware file by XORing with 0xAA
	try: # try to read and decode the malware file
		data = open(malware_path, "rb").read() # read the .malware file as bytes
		decoded = bytes(b ^ 0xAA for b in data) # decode by XORing each byte with 0xAA
		return decoded # return the decoded bytes
	except Exception as e: # if any error occurs during reading or decoding, print error and return none
		print(f"{Fore.RESET}{get_time()}{Fore.LIGHTBLACK_EX} | {Fore.RESET}[{Fore.RED}ERROR{Fore.RESET}] Failed to decode Malware{Fore.LIGHTBLACK_EX} |{Fore.RESET} {e}") # print error message
		return None # return none on error

def handle_command(token, chat_id, user_id, args, allowed_dm_user, group_id, topic_id, reports_dir="reports"): # function to handle the /get command from telegram
	is_dm = str(chat_id) == str(allowed_dm_user) # check if the message is a dm from the allowed user
	is_group = str(chat_id) == str(group_id) # check if the message is from the allowed group
	
	if not is_dm and not is_group: # if message is from neither allowed dm nor group, ignore and optionally send error message
		send_telegram(token, chat_id, text="<b>❌ You don't have Permission to use this Command</b>") # send error message to unauthorized user
		return # exit the command handler
	
	if not args: # if no arguments provided, send usage message
		send_telegram(token, chat_id, text="<b>❌ Usage:</b> <code>/get <md5|sha256></code>") # send usage message if no hash provided
		return # exit the command handler
	
	hash_input = " ".join(args) # join arguments to form the hash input
	
	print(f"{Fore.RESET}{get_time()}{Fore.LIGHTBLACK_EX} | {Fore.RESET}[{Fore.BLUE}BOT{Fore.RESET}] /get {Fore.BLUE}{hash_input}{Fore.RESET} from {'DM' if is_dm else 'GROUP'}") # print command usage
	
	malware_path = hash_to_exe(hash_input, reports_dir) # find the .malware file path based on the input hash
	
	if not malware_path: # if no matching malware file found, send error message
		send_telegram(token, chat_id, text=f"<b>❌ Sample not Found:</b> <code>{hash_input}</code>", topic_id=topic_id if is_group else None) # send error message if sample not found
		return # exit the command handler
	
	try: # try to decode the malware and send it as a password-protected zip file
		decoded = decode_malware(malware_path) # decode the .malware file to get the original executable bytes
		if not decoded: # if decoding failed, send error message
			send_telegram(token, chat_id, text="<b>❌ Failed to Decode Sample</b>", topic_id=topic_id if is_group else None) # send error message if decoding failed
			return # exit the command handler
		
		filename = os.path.basename(malware_path).replace(".malware", "") # create filename for the executable by removing .malware extension
		zip_name = filename + ".zip" # create filename for the zip file by appending .zip
		zip_path = malware_path.replace(".malware", ".zip") # create path for the zip file by replacing .malware with .zip
		
		with pyzipper.AESZipFile(zip_path, 'w', compression=pyzipper.ZIP_DEFLATED, encryption=pyzipper.WZ_AES) as zf: # create a new zip file to write the decoded executable
			zf.setpassword(b"infected") # set a password for the zip file to prevent accidental execution (password is "infected")
			zf.writestr(filename, decoded) # write the decoded executable bytes to the zip file with the appropriate filename
		
		sent = send_telegram(token, chat_id, text="<u>✅ <b>Here is your requested Sample!</b></u>\n└─ <b>Password:</b> <code>infected</code>", path=zip_path, topic_id=topic_id if is_group else None, filename=zip_name)
		if not sent: # if telegram rejected the upload
			send_telegram(token, chat_id, text="<b>❌ Failed to send Sample</b>", topic_id=topic_id if is_group else None) # tell the user the upload failed
			return # exit early so cleanup still runs
		print(f"{Fore.RESET}{get_time()}{Fore.LIGHTBLACK_EX} | {Fore.RESET}[{Fore.GREEN}SUCCESS{Fore.RESET}] Sent {zip_name} (password: infected)") # print success 
		
	except Exception as e:
		print(f"{Fore.RESET}{get_time()}{Fore.LIGHTBLACK_EX} | {Fore.RESET}[{Fore.RED}ERROR{Fore.RESET}] Failed to send Sample{Fore.LIGHTBLACK_EX} |{Fore.RESET} {e}") # print error
		send_telegram(token, chat_id, text=f"<b>❌ An unexpected error occurred, try again later.</b>", topic_id=topic_id if is_group else None) # send generic error message to user