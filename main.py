from fetcher.formatter import extract_data, build_message, strip_html, get_time
from fetcher import config, triage, telegram, banner, bot
from colorama import Fore
from datetime import datetime, timezone
import threading
import sqlite3
import time
import json
import sys
import os

REPORTS_DIR = "reports" # directory to store reports
SEEN_HASHES_DB = "seen_hashes.db" # sql db to store already processed SHA256 hashes

def init_db(): # function to initialize sql db
	try: # try to create db and table
		conn = sqlite3.connect(SEEN_HASHES_DB) # connect to db (creates if not exists)
		cursor = conn.cursor() # create cursor
		cursor.execute("""
			CREATE TABLE IF NOT EXISTS seen_hashes (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				sha256 TEXT UNIQUE NOT NULL,
				first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
			)
		""") # create table with sha256 as unique column
		cursor.execute("CREATE INDEX IF NOT EXISTS idx_sha256 ON seen_hashes(sha256)") # create index for fast lookups
		conn.commit() # commit changes
		conn.close() # close connection
	except Exception as e: # if error occurs
		print(f"{Fore.RESET}{get_time()}{Fore.LIGHTBLACK_EX} | {Fore.RESET}[{Fore.RED}ERROR{Fore.RESET}] Failed to initialize {Fore.RED}Database{Fore.LIGHTBLACK_EX} |{Fore.RESET} {e}") # print warning

def load_hashes(): # function to load previously seen sha256 hashes from db
	try: # try to read from db
		conn = sqlite3.connect(SEEN_HASHES_DB) # connect to db
		cursor = conn.cursor() # create cursor
		cursor.execute("SELECT sha256 FROM seen_hashes") # query all hashes
		hashes = set(row[0] for row in cursor.fetchall()) # convert to set
		conn.close() # close connection
		return hashes # return set of sha256 hashes
	except Exception as e: # if error occurs
		print(f"{Fore.RESET}{get_time()}{Fore.LIGHTBLACK_EX} | {Fore.RESET}[{Fore.RED}ERROR{Fore.RESET}] Failed to load seen {Fore.RED}Hashes{Fore.LIGHTBLACK_EX} |{Fore.RESET} {e}") # print error
		return set() # return empty set

def add_hash(sha256): # function to add a single sha256 hash to db
	try: # try to insert into db
		conn = sqlite3.connect(SEEN_HASHES_DB) # connect to db
		cursor = conn.cursor() # create cursor
		cursor.execute("INSERT OR IGNORE INTO seen_hashes (sha256) VALUES (?)", (sha256,)) # insert hash (ignore if duplicate)
		conn.commit() # commit changes
		conn.close() # close connection
	except Exception as e: # if error occurs
		print(f"{Fore.RESET}{get_time()}{Fore.LIGHTBLACK_EX} | {Fore.RESET}[{Fore.RED}ERROR{Fore.RESET}] Failed to add hash to {Fore.RED}Database{Fore.LIGHTBLACK_EX} |{Fore.RESET} {e}") # print error

def is_seen(sha256): # function to quickly check if hash has been seen
	try: # try to query db
		conn = sqlite3.connect(SEEN_HASHES_DB) # connect to db
		cursor = conn.cursor() # create cursor
		cursor.execute("SELECT 1 FROM seen_hashes WHERE sha256 = ?", (sha256,)) # query single hash
		result = cursor.fetchone() is not None # check if result exists
		conn.close() # close connection
		return result # return true if hash exists
	except Exception: # if error occurs
		return False # assume not seen if error

def triage_datetime(dt_raw): # parse triage datetime string to timezone aware datetime
	if not dt_raw: # if empty value
		return None # return no parsed datetime
	try: # try to parse known is  formats
		dt_text = str(dt_raw).strip() # normalize raw value to string
		if dt_text.endswith("Z"): # convert z suffix to utc offset for fromisoformat
			dt_text = dt_text[:-1] + "+00:00"
		dt = datetime.fromisoformat(dt_text) # parse iso timestamp
		if dt.tzinfo is None: # if timestamp has no timezone information
			dt = dt.replace(tzinfo=timezone.utc) # assume utc for consistency
		return dt # return parsed datetime
	except Exception: # if parsing fails
		return None # return no parsed datetime

def created_datetime(sample, api_key, cache): # resolve created datetime from search sample or overview fallback
	created_dt = triage_datetime(sample.get("created")) # prefer created value from search payload
	if created_dt: # if parse succeeded, return immediately
		return created_dt

	sid = sample.get("id", "") # get sample id for cache and overview lookup
	if not sid: # if no id exists
		return None # cannot resolve created datetime

	if sid in cache: # if resolved before
		return cache[sid] # reuse cached value

	overview = triage.get_overview(sid, api_key) # fallback to overview for accurate created timestamp
	if not overview: # if request failed
		cache[sid] = None # cache failure to avoid repeated requests
		return None # cant resolve created datetime without overview

	created_raw = (overview.get("sample", {}) or {}).get("created") or overview.get("created") # support both nesting styles
	resolved_dt = triage_datetime(created_raw) # parse created from overview payload
	cache[sid] = resolved_dt # cache resolved value (or None)
	return resolved_dt # return parsed datetime or None

def run_bot(token, chat_id, group_id, topic_id): # function to run bot command handler
	offset = None # offset for getting next updates
	
	while True: # infinite loop
		try:
			updates = bot.get_updates(token, offset) # fetch updates
			
			if updates and "result" in updates: # if we got updates
				for update in updates["result"]: # for each update
					offset = update["update_id"] + 1 # set offset for next update
					
					if "message" not in update: # if no message
						continue # skip this update
					
					msg = update["message"] # get message
					chat = msg.get("chat", {}).get("id") # get chat id
					user = msg.get("from", {}).get("id") # get user id
					text = msg.get("text", "").strip() # get message text
					
					if not text.startswith("/"): # if not a command
						continue # skip this message
					
					# Parse command
					parts = text.split() # split by spaces
					cmd = parts[0] # get command
					args = parts[1:] # get arguments
					
					if cmd == "/get": # if /get command
						bot.handle_command(token, chat, user, args, chat_id, group_id, topic_id) # handle the command
			
			time.sleep(1) # sleep before next update
		except Exception as e: # if error occurs
			print(f"{Fore.RESET}{get_time()}{Fore.LIGHTBLACK_EX} | {Fore.RESET}[{Fore.RED}ERROR{Fore.RESET}] Bot Error{Fore.LIGHTBLACK_EX} |{Fore.RESET} {e}") # print error

def process_sample(sample, api_key, tg_token, dest): # function to process a single sample
	sid = sample.get("id", "") # get the sample id
	filename = sample.get("filename") or f"{sid}.bin" # get filename or use sample id
	print(f"{Fore.RESET}{get_time()}{Fore.LIGHTBLACK_EX} | {Fore.RESET}[{Fore.CYAN}PROCESSING{Fore.RESET}] {sid} {Fore.LIGHTBLACK_EX}|{Fore.RESET} {filename}") # print the sample being processed

	overview = triage.get_overview(sid, api_key) # fetch overview from triage
	triage_rp = triage.get_report(sid, api_key) # fetch triage report from triage
	extracted = extract_data(sample, overview, triage_rp) # extract relevant data

	family = extracted["family"] if extracted["family"] != "N/A" else "unknown" # use family or unknown
	folder_id = extracted["sha256"] if extracted["sha256"] != "N/A" else sid # use sha256 or sample id
	sample_dir = os.path.join(REPORTS_DIR, family, folder_id) # construct the path
	os.makedirs(sample_dir, exist_ok=True) # create directory if it doesnt exist

	msg = build_message(sample, extracted) # build the formatted message
	rp_path = os.path.join(sample_dir, "report.txt") # path for plain text report
	with open(rp_path, "w", encoding="utf-8") as fh: # open file for writing
		fh.write(strip_html(msg)) # write plain text (no html tags like on telegram msg yk)
	print(f"{Fore.RESET}{get_time()}{Fore.LIGHTBLACK_EX} | {Fore.RESET}[{Fore.YELLOW}INFO{Fore.RESET}] Report saved to {Fore.YELLOW}{rp_path}{Fore.RESET}") # print the saved report path

	cfg_path = os.path.join(sample_dir, "config.json") # path for config JSON
	with open(cfg_path, "w", encoding="utf-8") as fh: # open file for writing
		json.dump(extracted, fh, indent=4) # write extracted data as JSON
	print(f"{Fore.RESET}{get_time()}{Fore.LIGHTBLACK_EX} | {Fore.RESET}[{Fore.YELLOW}INFO{Fore.RESET}] Config saved to {Fore.YELLOW}{cfg_path}{Fore.RESET}") # print the saved config path

	f_name = f"{filename}.malware" # .malware extension
	sample_path = os.path.join(sample_dir, f_name) # construct sample file path
	if triage.download_sample(sid, api_key, sample_path): # try to download the sample
		print(f"{Fore.RESET}{get_time()}{Fore.LIGHTBLACK_EX} | {Fore.RESET}[{Fore.YELLOW}INFO{Fore.RESET}] Sample saved to {Fore.YELLOW}{sample_path}{Fore.RESET}") # print the saved sample path
	else: # if download fails
		print(f"{Fore.RESET}{get_time()}{Fore.LIGHTBLACK_EX} | {Fore.RESET}[{Fore.RED}ERROR{Fore.RESET}] Failed to download sample") # print failure message

	for dest in dest: # for each destination (dm or group)
		telegram.send_telegram(tg_token, dest["chat_id"], text=msg, path=rp_path, topic_id=dest.get("thread_id"), filename=f"{folder_id}.txt") # send message
		time.sleep(0.5) # small delay between messages cuz of rate limiting
	
	return extracted.get("sha256") # return sha256 hash for tracking

def main(): # main function
	os.system("cls" if os.name == "nt" else "clear") # clear the screen
	banner.show() # display the banner
	init_db() # initialize sqlite database
	cfg = config.load() # load config.json

	triage_cfg = cfg.get("triage", {}) # get triage config section
	api_key = str(triage_cfg.get("api_key", "")).strip() # get api key and clean it
	interval = int(triage_cfg.get("poll_interval", 300)) # get poll interval (default 5 min)
	max_res = int(triage_cfg.get("max_results", 20)) # get max results per poll

	tg_cfg = cfg.get("telegram", {}) # get telegram config section
	tg_token = str(tg_cfg.get("bot_token", "")).strip() # get telegram bot token
	chat_id = str(tg_cfg.get("chat_id", "")).strip() # get personal chat id
	group_id = str(tg_cfg.get("group_id", "")).strip() # get group chat id
	topic_id = str(tg_cfg.get("topic_id", "")).strip() or None # get topic id (for forum groups)

	whitelist_hashes = set(cfg.get("debug", {}).get("whitelist_hashes", [])) # get debug whitelist hashes (if any) and convert to set for fast lookup

	dest = [] # list to store destinations
	if chat_id: # if personal chat id is set
		dest.append({"chat_id": chat_id}) # add personal chat as destination
	if group_id: # if group chat id is set
		dest.append({"chat_id": group_id, "thread_id": topic_id}) # add group as destination

	raw_family = triage_cfg.get("malware_family", []) # get malware_family setting (can be string or list)
	families = [raw_family] if isinstance(raw_family, str) else list(raw_family) # convert to list if string
	families = [fam.strip() for fam in families if str(fam).strip()] # clean and filter empty entries

	tags = [str(tag).strip() for tag in triage_cfg.get("malware_tags", []) if str(tag).strip()] # get tags and clean them

	if api_key == "": # if api key is not set
		print(f"{Fore.RESET}{get_time()}{Fore.LIGHTBLACK_EX} | {Fore.RESET}[{Fore.RED}ERROR{Fore.RESET}] Set your {Fore.RED}triage API Key{Fore.RESET} in config.json") # print error message
		sys.exit(1) # exit with error
	if tg_token == "": # if bot token is not set
		print(f"{Fore.RESET}{get_time()}{Fore.LIGHTBLACK_EX} | {Fore.RESET}[{Fore.RED}ERROR{Fore.RESET}] Set your {Fore.RED}Telegram Bot Token{Fore.RESET} in config.json") # print error message
		sys.exit(1) # exit with error
	if not dest: # if no destinations are configured
		print(f"{Fore.RESET}{get_time()}{Fore.LIGHTBLACK_EX} | {Fore.RESET}[{Fore.RED}ERROR{Fore.RESET}] Set at least one of {Fore.RED}chat_id{Fore.RESET} or {Fore.RED}group_id{Fore.RESET} in config.json") # print error message
		sys.exit(1) # exit with error

	# build the search query
	parts = [] # list to build query parts
	for fam in families: # for each malware family
		parts.append(f"family:{fam}") # add family filter to query
	for tag in tags: # for each tag
		parts.append(f"tag:{tag}") # add tag filter to query
		
	query = " ".join(parts) if parts else "score:>0" # build final query or use default

	seen_hashes = load_hashes() # load previously seen sha256 hashes from database
	initial_count = len(seen_hashes) # track how many we loaded

	print(Fore.LIGHTBLACK_EX + "=" * 75) # print separator
	print(f"{Fore.RESET}- Families : {Fore.LIGHTBLACK_EX}{', '.join(families) if families else 'Any'}{Fore.RESET}") # print configured families
	print(f"{Fore.RESET}- Tags     : {Fore.LIGHTBLACK_EX}{', '.join(tags) if tags else 'Any'}{Fore.RESET}") # print configured tags
	print(f"{Fore.RESET}- Query    : {Fore.LIGHTBLACK_EX}{query}{Fore.RESET}") # print final search query
	print(f"{Fore.RESET}- Interval : {Fore.LIGHTBLACK_EX}{interval}s{Fore.RESET}") # print poll interval
	print(f"{Fore.RESET}- Reports  : {Fore.LIGHTBLACK_EX}{REPORTS_DIR}/{Fore.RESET}") # print reports directory
	print(f"{Fore.RESET}- Seen     : {Fore.LIGHTBLACK_EX}{initial_count}{Fore.RESET}") # print number of previously seen samples loaded
	
	if chat_id: # if personal chat is configured
		print(f"{Fore.RESET}- DM       : {Fore.LIGHTBLACK_EX}{chat_id}{Fore.RESET}") # print personal chat ID
	if group_id: # if group chat is configured
		topic_display = f" / Topic {topic_id}" if topic_id else " / General" # format topic display
		print(f"{Fore.RESET}- Group    : {Fore.LIGHTBLACK_EX}{group_id}{topic_display}{Fore.RESET}") # print group info
	print(Fore.LIGHTBLACK_EX + "=" * 75) # print separator

	listener_started_at = datetime.now(timezone.utc) # only process samples created after listener startup
	listener_started_iso = listener_started_at.strftime("%Y-%m-%dT%H:%M:%SZ") # format startup time for logs

	print(f"\n{Fore.RESET}{get_time()}{Fore.LIGHTBLACK_EX} | {Fore.RESET}[{Fore.CYAN}START{Fore.RESET}] Listening for samples created after {Fore.CYAN}{listener_started_iso}{Fore.RESET}") # print info
	print(f"{Fore.RESET}{get_time()}{Fore.LIGHTBLACK_EX} | {Fore.RESET}[{Fore.CYAN}START{Fore.RESET}] Listener active, waiting for new samples...") # print info again lol

	threading.Thread(target=run_bot, args=(tg_token, chat_id, group_id, topic_id), daemon=True).start() # start bot thread for commands
	print(f"{Fore.RESET}{get_time()}{Fore.LIGHTBLACK_EX} | {Fore.RESET}[{Fore.CYAN}START{Fore.RESET}] Bot command handler started") # print info

	while True: # infinite loop
		try: # wrap in try-catch for stability
			res = triage.search_samples(api_key, query, max_res) # search triage api
			created_cache = {} # cache created timestamps resolved via overview per polling cycle

			if res and "data" in res: # if we got results
				all_samples = res["data"] # get the samples list
				new_samples = [] # list to store new samples with unprocessed hashes
				
				for sample in all_samples: # for each sample in results
					sid = sample.get("id", "") # get sample id for baseline check
					if sample.get("status", "reported") != "reported": # skip if not reported
						continue # skip incomplete samples
					try: # try to get sha256
						sha256 = sample.get("sha256") # get sha256 directly from sample response
						if sha256 and sha256 != "N/A":
							created_dt = created_datetime(sample, api_key, created_cache) # resolve created timestamp using fallback
							if created_dt and created_dt <= listener_started_at: # enforce startup cutoff with reliable timestamp
								continue # skip old sample even if it rotates into search later
							if sha256 in whitelist_hashes: # if hash is whitelisted, always include it
								new_samples.append(sample) # add to new samples list (don't check if seen)
							elif not is_seen(sha256): # if we got a valid, new hash and not whitelisted
								new_samples.append(sample) # add to new samples list
					except Exception: # if error
						pass # skip this sample

				if new_samples: # if there are new samples
					print(f"{Fore.RESET}{get_time()}{Fore.LIGHTBLACK_EX} | {Fore.RESET}[{Fore.GREEN}NEW{Fore.RESET}] Found {Fore.GREEN}{len(new_samples)}{Fore.RESET} new Sample{'s' if len(new_samples) > 1 else ''}") # print result

					for sample in new_samples: # for each new sample
						try: # try to process
							sha256 = process_sample(sample, api_key, tg_token, dest) # process the sample and get sha256
							if sha256 and sha256 != "N/A": # if we got a valid sha256
								if sha256 not in whitelist_hashes: # if hash is not whitelisted (only for debug reasons, ignore)
									add_hash(sha256) # add hash to database after successful processing
								else: # if hash is whitelisted
									seen_hashes.add(sha256) # add to in memory set so it wont be processed again this run
							time.sleep(1) # sleep 1 second before next sample
						except Exception as e: # if an error occurs
							sid = sample.get("id", "unknown") # get sample id for error message
							print(f"{Fore.RESET}{get_time()}{Fore.LIGHTBLACK_EX} | {Fore.RESET}[{Fore.RED}ERROR{Fore.RESET}] Error at {Fore.RED}{sid}{Fore.LIGHTBLACK_EX} |{Fore.RESET} {e}") # print error message
				else: # no new samples
					print(f"{Fore.RESET}{get_time()}{Fore.LIGHTBLACK_EX} | {Fore.RESET}[{Fore.YELLOW}INFO{Fore.RESET}] Checked {Fore.YELLOW}{len(all_samples)}{Fore.RESET} Samples {Fore.LIGHTBLACK_EX}|{Fore.RESET} Nothing New") # show poll status
			else: # if no data in response
				print(f"{Fore.RESET}{get_time()}{Fore.LIGHTBLACK_EX} | {Fore.RESET}[{Fore.YELLOW}INFO{Fore.RESET}] No samples found for Query {Fore.YELLOW}{query}{Fore.RESET}") # print info if no samples found
			time.sleep(interval) # sleep before next poll
		except Exception as e: # if loop error occurs
			print(f"{Fore.RESET}{get_time()}{Fore.LIGHTBLACK_EX} | {Fore.RESET}[{Fore.RED}ERROR{Fore.RESET}] Listener Error{Fore.LIGHTBLACK_EX} |{Fore.RESET} {e}") # print error
			time.sleep(interval) # sleep before retrying

if __name__ == "__main__": # if running directly
	main() # run main function
