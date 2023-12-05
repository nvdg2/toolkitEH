import os
from pprint import pprint
from bs4 import BeautifulSoup as bs
from urllib.parse import urljoin
import requests
from datetime import datetime
import json
import pathlib
import argparse
# Code is gebaseerd op de volgende bron: https://systemweakness.com/building-an-xss-scanner-with-python-detecting-cross-site-scripting-vulnerabilities-by-tommaso-69d4c9e04d72

def get_forms_from_webpage(url):
    page = bs(requests.get(url).content, "html.parser")
    forms = page.find_all("form")
    return forms

def get_details_of_form(form):
    form_details={}
    action = form.attrs.get("action").lower()
    method = form.attrs.get("method", "get").lower()
    inputs = []
    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        input_value = input_tag.attrs.get("value", "")
        inputs.append({"type": input_type, "name": input_name, "value": input_value})
    form_details["action"] = action
    form_details["method"] = method
    form_details["inputs"] = inputs
    return form_details

def submit_form(form_details, url, value):
    target_url = urljoin(url, form_details["action"])
    inputs = form_details["inputs"]
    data = {}
    for input in inputs:
        if input["type"] == "text" or input["type"] == "search":
            input["value"] = value
        input_name = input["name"]
        input_value = input["value"]
        if input_name and input_value:
            data[input_name] = input_value
    if form_details["method"] == "post":
        return requests.post(target_url, data=data)
    return requests.get(target_url, params=data)

def perform_XSS_scan(url):
    xss_payloads=[]
    print("Starting XSS scan")
    with open("resources/xss_payload.txt","r") as file:
        while True:
            line=file.readline().replace("\n","")
            if len(line) == 0:
                break
            xss_payloads.append(line)

    try:
        forms=get_forms_from_webpage(url)
    except requests.exceptions.MissingSchema as e:
        return(f"Error: {str(e)}")
    
    if len(forms) == 0:
        return {"message":"No forms found"}
    
    for form in forms:
        form_details=get_details_of_form(form)
    
        for payload in xss_payloads:
            response=submit_form(form_details,url,payload)
            if payload in response.content.decode():
                print("XSS vulnerabilities detected")
                result={
                    "site": url,
                    "message":"XSS vulnerability detected!",
                    "payload":payload,
                    "form_details":form_details
                }

                timestamp = datetime.now().strftime("%d-%m-%Y_%H:%M:%S")
                xss_dir = pathlib.Path("logs/xss_scans")
                xss_dir.mkdir(exist_ok=True,parents=True)
                save_location=xss_dir/f"XSS_scan_{timestamp}.json"
                os.chown(xss_dir,1000,1000)
                with save_location.open("w") as json_file_raw:
                    json.dump(result, json_file_raw)

                return result
        print("No XSS vulnerabilities detected")
        return {"message":"No XSS vulnerabilities detected"}

def main():
    parser = argparse.ArgumentParser(description="Script om een form te testen op cross site scripting zwakheden.")
    parser.add_argument("url_with_form", help="URL van pagina waar form in staat.")

    args = parser.parse_args()

    perform_XSS_scan(args.url_with_form)

if __name__ == "__main__":
    main()
