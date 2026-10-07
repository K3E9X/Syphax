"""Deriving a public PoC's command line.

A public exploit is a CLI program. Running it bare produced:
    usage: poc.py [-h] -t TARGET [-p PORT]
    poc.py: error: the following arguments are required: -t/--target
exit 2, nothing proven, finding stuck at "unverified". These pin the inference.
"""
from app.sandbox.invocation import build_argv, detect_options, split_target

ARGPARSE_TP = '''
import argparse
p = argparse.ArgumentParser()
p.add_argument("-t", "--target", required=True, help="target host")
p.add_argument("-p", "--port", default=22, type=int)
'''

ARGPARSE_URL = '''
import argparse
p = argparse.ArgumentParser()
p.add_argument("-u", "--url", required=True)
'''

POSITIONAL = 'import sys\ntarget = sys.argv[1]\n'

NO_ARGS = 'import requests\nrequests.get("http://127.0.0.1")\n'


def test_target_and_port_flags():
    assert build_argv(ARGPARSE_TP, "62.210.216.154:22") == [
        "--target", "62.210.216.154", "--port", "22"]


def test_target_flag_without_port_in_finding():
    assert build_argv(ARGPARSE_TP, "example.com") == ["--target", "example.com"]


def test_url_option_gets_the_whole_url():
    assert build_argv(ARGPARSE_URL, "https://h.example/x") == [
        "--url", "https://h.example/x"]


def test_positional_poc():
    assert build_argv(POSITIONAL, "1.2.3.4:22") == ["1.2.3.4:22"]


def test_poc_that_takes_nothing_gets_nothing():
    assert build_argv(NO_ARGS, "1.2.3.4:22") == []


def test_help_only_option_is_not_a_target():
    opts = detect_options('p.add_argument("-h", "--help", action="help")')
    assert opts["target"] is None


def test_split_target():
    assert split_target("1.2.3.4:22") == ("1.2.3.4", "22", None)
    assert split_target("https://h.example/x") == ("h.example", None, "https://h.example/x")
    assert split_target("") == ("", None, None)


def test_empty_target_yields_no_argv():
    assert build_argv(ARGPARSE_TP, "") == []
