import requests
import argparse
from datetime import datetime
import json
import pathlib
import os

def perform_wordlist_attack(target, list):
    print(list)
    try:
        wordlist=read_list(f"resources/wordlists/{list}.txt")
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

def log_results(urls):
    timestamp = datetime.now().strftime("%d-%m-%Y_%H:%M:%S")
    xss_dir = pathlib.Path("logs/wordlist_attack")
    xss_dir.mkdir(exist_ok=True,parents=True)
    save_location=xss_dir/f"wordlist_attack_{timestamp}.json"
    os.chown(xss_dir,1000,1000)
    with save_location.open("w") as json_file_raw:
        json.dump(urls, json_file_raw)

def main():
    parser = argparse.ArgumentParser(description="Website wordlist attack")
    parser.add_argument("target", help="target url for wordlist attack")
    parser.add_argument("list", help="use the standard wordlist",choices=["standard", "swagger"])
    args = parser.parse_args()
    
    perform_wordlist_attack(target=args.target, list=args.list)

if __name__=="__main__":
    main()