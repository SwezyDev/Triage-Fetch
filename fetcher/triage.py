from .formatter import get_time
from colorama import Fore
import requests

API = "https://tria.ge/api/v0" # base api for triage

def _get(path, api_key, params=None): # internal function for get requests
	header = {"Authorization": f"Bearer {api_key}"} # create auth header with api key
	try: # try to make request
		req = requests.get(f"{API}/{path}", headers=header, params=params, timeout=30) # make GET request
		if req.status_code == 200: # if successful
			return req.json() # return json response
		if req.status_code not in (403, 404): # if not a permission/not found error
			print(f"{Fore.RESET}{get_time()}{Fore.LIGHTBLACK_EX} | {Fore.RESET}[{Fore.RED}ERROR{Fore.RESET}] API {Fore.RED}{path}{Fore.LIGHTBLACK_EX} |{Fore.RESET} HTTP {req.status_code}") # print error code
		return None # return none on error
	except Exception as e: # if request fails
		print(f"{Fore.RESET}{get_time()}{Fore.LIGHTBLACK_EX} | {Fore.RESET}[{Fore.RED}ERROR{Fore.RESET}] Request Error ({Fore.RED}{path}{Fore.RESET}){Fore.LIGHTBLACK_EX} |{Fore.RESET} {e}") # print error message
		return None # return none

def search_samples(api_key, query, limit): # function to search for malware samples
	return _get("search", api_key, {"query": query, "limit": limit}) # call _get with search parameters

def get_overview(sample_id, api_key): # function to get sample overview
	return _get(f"samples/{sample_id}/overview.json", api_key) # get overview endpoint

def get_report(sample_id, api_key): # function to get triage report
	return _get(f"samples/{sample_id}/reports/triage", api_key) # get triage report endpoint

def download_sample(sample_id, api_key, path): # function to download the actual malware file
	header = {"Authorization": f"Bearer {api_key}"} # create auth header
	try: # try to download
		req = requests.get(f"{API}/samples/{sample_id}/sample", headers=header, timeout=60, stream=True) # make get request to download endpoint
		if req.status_code == 200: # if successful
			raw = b"".join(req.iter_content(chunk_size=8192)) # read file in chunks
			xored = bytes(b ^ 0xAA for b in raw) # decrypt by XORing with 0xAA to protect against accidental execution lol
			with open(path, "wb") as f: # open file for writing bytes
				f.write(xored) # write decrypted data to file
			print(f"{Fore.RESET}{get_time()}{Fore.LIGHTBLACK_EX} | {Fore.RESET}[{Fore.GREEN}SUCCESS{Fore.RESET}] Sample Downloaded ({Fore.GREEN}{sample_id}{Fore.RESET}){Fore.LIGHTBLACK_EX}") # print success message
			return True # return success
		print(f"{Fore.RESET}{get_time()}{Fore.LIGHTBLACK_EX} | {Fore.RESET}[{Fore.RED}ERROR{Fore.RESET}] Sample Download Failed ({Fore.RED}{sample_id}{Fore.RESET}){Fore.LIGHTBLACK_EX} |{Fore.RESET} {req.status_code}") # print error status
		return False # return failure
	except Exception as e: # if request fails
		print(f"{Fore.RESET}{get_time()}{Fore.LIGHTBLACK_EX} | {Fore.RESET}[{Fore.RED}ERROR{Fore.RESET}] Sample Download Error{Fore.LIGHTBLACK_EX} |{Fore.RESET} {e}") # print error message
		return False # return failure

