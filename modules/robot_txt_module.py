import requests
import argparse

def perform_wordlist_attack(target, list):
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
    return found_urls

def read_list(list_path):
    wordlist=[]
    with open(list_path,"r") as list:
        while True:
            line=list.readline()
            if line=="":
                break
            wordlist.append(line.replace("\n",""))
    return wordlist

def main():
    parser = argparse.ArgumentParser(description="Website wordlist attack")
    parser.add_argument("target", help="target url for wordlist attack")
    parser.add_argument("list", help="use the standard wordlist",choices=["standard", "swagger"])
    args = parser.parse_args()
    match args.list:
        case "standard":
            perform_wordlist_attack(target=args.target, wordlist=args.list)
        case "swagger":
            perform_wordlist_attack(target=args.target, wordlist=args.list)

if __name__=="__main__":
    main()