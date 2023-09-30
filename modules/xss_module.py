import os
from pprint import pprint
from bs4 import BeautifulSoup as bs
from urllib.parse import urljoin
import requests
# Code is gebaseerd op de volgende bron: https://systemweakness.com/building-an-xss-scanner-with-python-detecting-cross-site-scripting-vulnerabilities-by-tommaso-69d4c9e04d72
def get_web_page(url):
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


if __name__=="__main__":

    forms=get_web_page("http://127.0.0.1:5000/nmap/portscan")
    for form in forms:
        form_details = get_details_of_form(form)
        print(submit_form(form_details, "http://127.0.0.1:5000/nmap/portscan","test"))