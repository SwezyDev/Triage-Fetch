def snipe(c2s): # function to do what ever you want with the C2s fetched from a sample
   domain_ip = c2s.get("domain_ip", []) # get domain/ip list
   pastebins = c2s.get("pastebin", []) # get pastebin list
   telegram_tokens = c2s.get("telegram_tokens", []) # get telegram tokens list
   discord_tokens = c2s.get("discord_tokens", []) # get discord tokens list

   # you can do anything with them... like sort them in a list or check if host is reachable/online etc

   # Example to show all data fetched from the sample:
   #  print("- Domain/IPs:", domain_ip) # print domain/ip list
   #  print("- Pastebins:", pastebins) # print pastebin list
   #  print("- Telegram Tokens:", telegram_tokens) # print telegram tokens list
   #  print("- Discord Tokens:", discord_tokens) # print discord tokens list
