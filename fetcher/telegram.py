from .formatter import get_time
from colorama import Fore
import requests

API = "https://api.telegram.org/bot{token}/{method}" # telegram bot api
CAPTION_LIMIT = 1024  # telegram caption max length
MESSAGE_LIMIT = 4096  # telegram message max length

def send_telegram(token, chat_id, text=None, path=None, topic_id=None, filename=None): # function to send message or file to telegram
	payload = {"chat_id": chat_id} # build base payload

	if topic_id: # if sending to a forum topic
		payload["message_thread_id"] = topic_id # add topic/thread id

	try: # try to send message or file
		if path: # if path provided, send as document
			url = API.format(token=token, method="sendDocument") # build senddocument url
			if text: # if text provided
				if len(text) > CAPTION_LIMIT: # if text is too long for caption
					msg_url = API.format(token=token, method="sendMessage") # build sendmessage url
					msg_payload = {"chat_id": chat_id, "text": text[:MESSAGE_LIMIT], "parse_mode": "HTML"} # payload for text message
					if topic_id: # if sending to a forum topic, add topic/thread id to message payload as well
						msg_payload["message_thread_id"] = topic_id # add topic/thread id to message if needed
					requests.post(msg_url, data=msg_payload) # send text message
				else: # if text fits in caption, add to document payload
					payload["caption"] = text # add caption to payload if it fits
					payload["parse_mode"] = "HTML" # set parse mode to html for caption formatting

			with open(path, "rb") as f: # open file for reading in binary mode
				doc = (filename, f) if filename else f # if filename provided, use it, otherwise just send file without name
				req = requests.post(url, data=payload, files={"document": doc}) # send post request with file
		else:
			url = API.format(token=token, method="sendMessage") # build sendmessage url

			payload["text"] = (text or "")[:MESSAGE_LIMIT] # add text to payload, use empty string if none provided, truncate to telegram limit
			payload["parse_mode"] = "HTML" # set parse mode to html for text formatting

			req = requests.post(url, data=payload) # send post request to sendmessage endpoint

		if not req.ok: # if request failed
			print(f"{Fore.RESET}{get_time()}{Fore.LIGHTBLACK_EX} | {Fore.RESET}[{Fore.RED}ERROR{Fore.RESET}] Telegram API {Fore.RED}{req.status_code} {Fore.LIGHTBLACK_EX}|{Fore.RESET} {req.text[:120]}") # print error
			return False # return failure
		return True # return success
	except Exception as e: # if exception occurs
		print(f"{Fore.RESET}{get_time()}{Fore.LIGHTBLACK_EX} | {Fore.RESET}[{Fore.RED}ERROR{Fore.RESET}] Telegram request failed {Fore.RED}Failed {Fore.LIGHTBLACK_EX}|{Fore.RESET} {e}") # print error
		return False # return failure