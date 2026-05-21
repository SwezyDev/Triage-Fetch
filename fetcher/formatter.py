from datetime import datetime
from colorama import Fore
from .sniper import snipe
import threading
import requests
import json
import re

def get_time(): # function to get current time as string
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S") # format as YYYY-MM-DD HH:MM:SS

def strip_html(text): # function to remove html tags
	return re.sub(r"<[^>]+>", "", text) # regex to remove anything between < and >

def get_size(bytes): # function to format file size
	if bytes is None: # if size is none
		return "N/A" # return N/A
	if bytes >= 1024 * 1024: # if size is >= 1mb
		return f"{bytes / (1024 * 1024):.0f} MB ({bytes})" # return mbs
	if bytes >= 1024: # if size is >= 1kb
		return f"{bytes / 1024:.0f} KB ({bytes})" # return kbs
	return f"{bytes} B ({bytes})" # return bytes

def get_datetime(date): # function to format datetime string from api into something more readable
	if not date: # if date is empty
		return "N/A" # return N/A
	try: # try to parse
		dt = datetime.fromisoformat(date.replace("Z", "+00:00")) # parse iso format
		h = dt.hour % 12 or 12 # convert to 12 hour format
		ampm = "AM" if dt.hour < 12 else "PM" # am or pm
		return f"{dt.month}/{dt.day}/{dt.year}, {h}:{dt.strftime('%M')}:{dt.strftime('%S')} {ampm}" # format as MM/DD/YYYY, H:MM:SS AM/PM
	except Exception: # if fails
		return date # return original string
	
def get_score(score): # function to format malware score
	if not score: # if score is None/0
		return "0.00%" # return 0%
	sr = float(score) # convert to float
	# btw tria.ge scores are on a 0-10 scale so multiply by 10 to get percentage
	return f"{sr * 10:.2f}%" if sr <= 10 else f"{sr:.2f}%" # format with 2 decimals

def get_c2s(cfg, c2_dict): # helper function to extract c2 addresses from config dicts
	for key in ("c2", "c2s", "servers", "domains", "hosts"): # common key names for c2 lists
		for c2 in cfg.get(key, []): # for each C2 value in that list
			if isinstance(c2, dict): # if C2 is a dict (has host/port)
				host = c2.get("host", "") or c2.get("ip", "") or c2.get("domain", "") # get host/ip/domain
				port = c2.get("port", "") # get port
				value = f"{host}:{port}" if port else host # format as host:port or just host
			elif isinstance(c2, str): # if c2 is already a string
				value = c2 # dont change anything
			else: # if something unexpected
				continue # skip it
			if value and value not in c2_dict["domain_ip"]: # if not empty and not already in list
				c2_dict["domain_ip"].append(value) # add to domain_ip list

	attr = cfg.get("attr", {}) # get the attr dict from config
	if isinstance(attr, dict): # if attr is a dict
		host = attr.get("host", "") or attr.get("ip", "") or attr.get("domain", "") # look for host/ip/domain in attr
		port = attr.get("port", "") # look for port in attr
		if host: # if we found a host
			value = f"{host}:{port}" if port else host # format as host:port
			if value not in c2_dict["domain_ip"]: # if not already in list
				c2_dict["domain_ip"].append(value) # add to domain_ip list

		pastebin_url = attr.get("pastebin_url", "") # look for pastebin url in attr
		if pastebin_url: # if pastebin url exists
			if pastebin_url not in c2_dict["pastebin"]: # if URL not already in list
				c2_dict["pastebin"].append(pastebin_url) # add to pastebin list
			for value in pastebin_c2_re(pastebin_url): # fetch c2s from pastebin
				if value not in c2_dict["domain_ip"]: # if not already in list
					c2_dict["domain_ip"].append(value) # add to domain_ip list

		for key in ("telegram_token", "bot_token", "telegram", "tg_token", "token"): # keys for tg tokens
			get = attr.get(key, "") # get value from attr
		
			if get: # if value exists
				if "api.telegram.org" in str(get): # if its a full telegram API URL
					value = f"telegram:{get}" # format full API URL
		
				elif tg_token_re(get): # if it looks like a tg bot token
					value = f"telegram:{get}" # format as telegram:token
		
				else: # if it doesnt match token format or API URL
					continue # skip this value
		
				if value not in c2_dict["telegram_tokens"]: # if not already in list
					c2_dict["telegram_tokens"].append(value) # add to telegram list
		
				break # stop looking for other tg keys

		for key in ("discord_webhook", "webhook_url", "webhook", "discord", "discord_token"): # keys for dc webhooks
			get = attr.get(key, "") # get value from attr
			if get: # if value exists
				if get not in c2_dict["discord_tokens"]: # if not already in list
					c2_dict["discord_tokens"].append(get) # add to discord list
				break # stop looking for other dc keys

def tg_token_re(val): # helper function to validate tg token format
	return bool(re.match(r"^\d+:[A-Za-z0-9_-]{35,}$", str(val))) # match token format

def pastebin_c2_re(url): # helper function to fetch c2 from pastebin
	try: # try to fetch
		req = requests.get(url, timeout=10) # get pastebin content
		if not req.ok: # if request failed
			print(f"{Fore.RESET}{get_time()}{Fore.LIGHTBLACK_EX} | {Fore.RESET}[{Fore.RED}ERROR{Fore.RESET}] Pastebin fetch Failed ({Fore.RED}{url}{Fore.RESET}){Fore.LIGHTBLACK_EX} |{Fore.RESET} {req.status_code}") # print error
			return [] # return empty list
		text = req.text.strip() # get text and strip whitespace
		res = [] # list to store c2s
		for line in text.splitlines(): # for each line in pastebin
			line = line.strip() # strip whitespace
			if not line: # if line is empty
				continue # skip it
			res.append(line) # add line as c2
		return res # return all lines as c2s
	except Exception as e: # if any error occurs
		print(f"{Fore.RESET}{get_time()}{Fore.LIGHTBLACK_EX} | {Fore.RESET}[{Fore.RED}ERROR{Fore.RESET}] Pastebin fetch Error{Fore.LIGHTBLACK_EX} |{Fore.RESET} {e}") # print error
		return [] # return empty list

def extract_data(sample, overview, triage_rpt): # function to extract all relevant data from apis
	res = {
    "family": "N/A",
    "c2s": {
        "domain_ip": [],
        "pastebin": [],
        "telegram_tokens": [],
        "discord_tokens": [],
    },
    "score": 0,
    "tags": [],
    "md5": "N/A",
    "sha256": "N/A",
    "size": None,
    "created": "",
    "configs": [],
	} # extracted data dict

	
	res["size"] = sample.get("size") # get size from search result
	res["created"] = sample.get("created", "") # get created date from search result

	for src in [sample, overview]: # for both sample and overview
		if not src: # if source is None
			continue # skip
		
		obj = src.get("sample", src) # get nested "sample" or use source directly
		
		if obj.get("md5") and res["md5"] == "N/A": # if md5 exists and not set yet
			res["md5"] = obj["md5"] # set md5 if not set
			
		if obj.get("sha256") and res["sha256"] == "N/A": # if sha256 exists and not set yet
			res["sha256"] = obj["sha256"] # set sha256 if not set
			
		if obj.get("size") and res["size"] is None: # if size exists and not set yet
			res["size"] = obj["size"] # set size if not set
			
		if obj.get("created") and not res["created"]: # if created exists and not set yet
			res["created"] = obj["created"] # set created if not set

	if overview: # if overview was fetched
		ov_sample = overview.get("sample", {}) # get nested sample object

		score_value = ov_sample.get("score") or overview.get("score") # get score from overview
		if score_value: # if score exists
			res["score"] = score_value # set score

		tag_set = set(res["tags"]) # init tag set
		for src in [ov_sample.get("tags", []), overview.get("tags", []),sample.get("tags", [])]: # for each tags list in sample and overview
			tag_set.update(src) # add all tags to set
			
		for tgt in overview.get("targets", []): # for each analysis target
			tag_set.update(tgt.get("tags", [])) # add target tags to set
			
			if tgt.get("md5") and res["md5"] == "N/A":
				res["md5"] = tgt["md5"] # set from target
				
			if tgt.get("sha256") and res["sha256"] == "N/A":
				res["sha256"] = tgt["sha256"] # set from target
				
			if tgt.get("size") and res["size"] is None:
				res["size"] = tgt["size"] # set from target

		res["tags"] = sorted(tag_set) # store sorted tags

		extracted_items = list(overview.get("extracted", [])) # get extracted configs
		for tgt in overview.get("targets", []): # for each analysis target
			extracted_items.extend(tgt.get("extracted", [])) # add targets extracted configs

		for item in extracted_items: # for each extracted config
			cfg = item.get("config", {}) # get config dict
			if cfg: # if config exists
				res["configs"].append(cfg) # save config
				
			if cfg.get("family") and res["family"] == "N/A": # if family not set
				res["family"] = cfg["family"] # set family from config
				
			get_c2s(cfg, res["c2s"]) # extract c2s from this config

	if triage_rpt: # if triage report was fetched
		if not res["score"]: # if score not set yet
			res["score"] = triage_rpt.get("score", 0) # get from triage report
			
		for item in triage_rpt.get("extracted", []): # for each extracted config in report
			cfg = item.get("config", {}) # get config dict
			
			if cfg and cfg not in res["configs"]: # if config and not already saved
				res["configs"].append(cfg) # save config
				
			if cfg.get("family") and res["family"] == "N/A": # if family not set
				res["family"] = cfg["family"] # set family
				
			get_c2s(cfg, res["c2s"]) # extract c2s from config

	if res["family"] == "N/A": # if family still not found
		for tag in res["tags"]: # for each tag
			if tag.startswith("family:"): # if tag is family:xxx format
				res["family"] = tag.split(":", 1)[1] # extract family name
				break # stop searching

	return res # return all extracted data

def build_message(sample, extracted): # function to build the formatted tg message
	sid = sample.get("id", "N/A") # get sample id
	filename = sample.get("filename") or f"{sid}.bin" # get filename or use id
	is_pub = not sample.get("private", True) # check if sample is public
	sha256 = extracted["sha256"] # get sha256 hash

	tags = [f"#{t.split(':')[-1].replace('-', '_')}" for t in extracted["tags"]] + ["#MalwareFetcherV1"] # format tags with # and underscores

	c2s = extracted["c2s"] # get structured c2 dict
	domain_ip_str = ", ".join(c2s["domain_ip"]) if c2s["domain_ip"] else None # format domain/ip list or None if empty
	pastebin_str = ", ".join(c2s["pastebin"]) if c2s["pastebin"] else None # format pastebin list or None if empty
	tg_str = ", ".join(c2s["telegram_tokens"]) if c2s["telegram_tokens"] else None # format telegram tokens or None if empty
	dc_str = ", ".join(c2s["discord_tokens"]) if c2s["discord_tokens"] else None # format discord tokens or None if empty

	vt_link = (
		f"https://www.virustotal.com/gui/file/{sha256}/community"
		if sha256 != "N/A"
		else "<code>❌</code>"
	) # link to virustotal if we have a sha256, else show ❌

	score_str = get_score(extracted["score"]) # format score as percentage
	score_display = "💯" if float(extracted["score"]) >= 10 else score_str # show 💯 for 100% score, else percentage

	dump_section = "" # init config dump section
	if extracted["configs"]: # if configs were extracted
		dump_json = json.dumps(extracted["configs"], indent=2) # format configs
		dump_section = f"<u>📦 <b>Config Dump</b></u>\n<pre>{dump_json}</pre>\n\n" # add config section to message

	c2_section = f"<u>📡 <b>Command and Control Servers</b></u>\n" # start c2 section
	
	if not domain_ip_str and not pastebin_str and not tg_str and not dc_str: # if no c2s found at all
		c2_section += "├─ <code>No C2s Found</code>\n" # show no c2s found
	
	if domain_ip_str: # if we have domain/ip c2s
		c2_section += f"├─ <b>IPs/Domains:</b> <code>{domain_ip_str}</code>\n" # always show domain/ip line

	if pastebin_str: # if pastebin urls exist
		c2_section += f"├─ <b>Pastebin:</b> <code>{pastebin_str}</code>\n" # add pastebin line

	if tg_str: # if telegram tokens exist
		c2_section += f"├─ <b>Telegram:</b> <code>{tg_str}</code>\n" # add telegram line

	if dc_str: # if discord tokens exist
		c2_section += f"├─ <b>Discord:</b> <code>{dc_str}</code>\n" # add discord line

	c2_section = c2_section.rstrip("\n") # strip trailing newline
	lines = c2_section.split("\n") # split into lines to fix last prefix
	lines[-1] = lines[-1].replace("├─", "└─", 1) # replace last ├─ with └─
	c2_section = "\n".join(lines) + "\n\n" # rejoin lines and add spacing

	threading.Thread(target=snipe, args=(c2s,), daemon=True).start() # start snipe in background

	return ( # build and return the complete message
		f"<u>🦠 <b>Malware Fetcher</b></u>\n" # title basically
		f"├─ <b>Filename:</b> <code>{filename}</code>\n" # filename
		f"├─ <b>Threat Score:</b> <code>{score_display}</code>\n" # threat score
		f"├─ <b>Family:</b> <code>{extracted['family']}</code>\n" # malware family
		f"├─ <b>Size:</b> <code>{get_size(extracted['size'])}</code>\n" # file size
		f"├─ <b>First seen:</b> <code>{get_datetime(extracted['created'])}</code>\n" # first seen date
		f"├─ <b>MD5:</b> <code>{extracted['md5']}</code>\n" # md5 hash
		f"├─ <b>Sha256:</b> <code>{sha256}</code>\n" # sha256 hash
		f"└─ <b>Public:</b> <code>{'Yes' if is_pub else 'No'}</code>\n\n" # public or private
		f"{c2_section}" # c2 section
		f"{dump_section}" # config dump section (if any)
		f"<u>🔗 <b>Links</b></u>\n" # links section
		f"├─ <b>Triage:</b> https://tria.ge/{sid}/behavioral1\n" # triage link
		f"└─ <b>VirusTotal:</b> {vt_link}\n\n" # virustotal link
		f"<u>🏷️ <b>Tags</b></u>\n" # tags section
		f"└─ {', '.join(tags)}" # all tags
	)