from colorama import Fore
import sys

def decode_malware(malware_path): # function to decode the .malware file by XORing with 0xAA
	try: # try to read and decode the malware file
		data = open(malware_path, "rb").read() # read the .malware file as bytes
		decoded = bytes(b ^ 0xAA for b in data) # decode by XORing each byte with 0xAA

		with open(malware_path.replace(".malware", ""), "wb") as f: # write the decoded data to a new file and remove the .malware extension
			f.write(decoded) # write the decoded bytes to the new file

		print(f"{Fore.RESET}[{Fore.GREEN}+{Fore.RESET}] Sample Decoded saved to {Fore.GREEN}{malware_path.replace('.malware', '')}{Fore.RESET}") # print success message
	except Exception as e: # if any error occurs during reading or decoding, print error and return none
		print(f"[{Fore.RED}!{Fore.RESET}] Failed to decode Malware{Fore.LIGHTBLACK_EX} |{Fore.RESET} {e}") # print error message
		sys.exit(1) # exit with error code

if __name__ == "__main__": # if script is run directly
	if len(sys.argv) != 2: # check if exactly one argument (the malware file path) is provided
		print(f'{Fore.CYAN}Usage: {sys.argv[0]} "path to .malware file"{Fore.RESET}') # print usage message if not
		sys.exit(1) # exit with error code

	malware_path = sys.argv[1] # get the malware file path from command line argument
	decode_malware(malware_path) # call the decode function with the provided path