import requests
import argparse
from datetime import datetime
import json
import pathlib
import os

def perform_wordlist_attack(target, list_path):
    try:
        wordlist=read_list(list_path)
    except:
        return "worldlist not found"
    try:
        req = requests.get(f"{target}/")
    except:
        return "invalid url"
    
    found_urls = []
    invalid_urls = []
    if target.endswith("/"):
        target = target[:-1]
    for word in wordlist:
        print(f"Scanning url: {target}{word}")
        try:
            req = requests.get(f"{target}{word}")
            if req.status_code == 200:
                print(f"Found: {target}{word}")
                found_urls.append(f"{target}{word}")
        except:
            invalid_urls.append(f"{target}{word}")

    if len(found_urls)==0:
        print("No valid urls found")
    if len(invalid_urls)>0:
        print("The following urls were invalid:")
        for url in invalid_urls:
            print(url)
    result={
        "site":target,
        "found_urls":found_urls
    }
    log_results(result)
    return result

def read_list(list_path):
    wordlist=[]
    with open(list_path,"r") as list:
        while True:
            line=list.readline()
            if line=="":
                break
            wordlist.append(line.replace("\n",""))
    return wordlist

def log_results(result):
    timestamp = datetime.now().strftime("%d-%m-%Y_%H:%M:%S")
    xss_dir = pathlib.Path("logs/wordlist_attack")
    xss_dir.mkdir(exist_ok=True,parents=True)
    save_location=xss_dir/f"wordlist_attack_{timestamp}.json"
    os.chown(xss_dir,1000,1000)
    with save_location.open("w") as json_file_raw:
        json.dump(result, json_file_raw)

def main():
    parser = argparse.ArgumentParser(description="Brute force wordlist attack uitvoeren op een website")
    parser.add_argument("target", help="doelurl voor wordlist attack")
    parser.add_argument("-l", "--standard_list_choice", help="Standaard keuzelijst voor bruteforce aanval. Indien geen -c flag gebruikt",choices=["standard", "swagger"])
    parser.add_argument("-c", "--custom", action="store_true", default=False, help="Gebruik deze flag om aan te geven dat een custom lijst opgegeven wordt")
    parser.add_argument("-p", "--list_path", help="Locatie van custom lijst")
    
    args = parser.parse_args()
    
    if args.custom:
        perform_wordlist_attack(target=args.target, list_path=args.list_path)
    else:
        perform_wordlist_attack(target=args.target, list_path=f"resources/wordlists/{args.standard_list_choice}.txt")
        

if __name__=="__main__":
    main()
