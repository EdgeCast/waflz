#!/usr/bin/env python3
""" Fake origin:
    Responds to any request. Response based on a few rules:

    1) if `x-waflz-set-response` passed:
        1.1) responds with the file text if given a file name
        1.2) responds with the raw value otherwise

        *NOTE*: this will set all static response to this value going forward.

    2) if `x-waflz-respond-with` passed:
        2.1) responds with the file text if given a file name
        2.2) responds with the raw value otherwise

    3) respond with default/set static response
"""
# ------------------------------------------------------------------------------
# std imports
# ------------------------------------------------------------------------------
import argparse
from pathlib import Path
# ------------------------------------------------------------------------------
# third party imports
# ------------------------------------------------------------------------------
from flask import Flask, request, Response
# ------------------------------------------------------------------------------
# create the flask app
# ------------------------------------------------------------------------------
G_App = Flask(__name__)
G_Static_Response = "Hello :D\n"
G_Static_Status = 200
G_DYNAMIC_RESPONSE_HEADER = 'x-waflz-respond-with'
G_SET_RESPONSE_HEADER = 'x-waflz-set-response'
G_SET_RESPONSE_STATUS_HEADER = 'x-waflz-set-status'
G_DYNAMIC_RESPONSE_STATUS_HEADER = 'x-waflz-respond-with-status'
# ------------------------------------------------------------------------------
# helper function
# ------------------------------------------------------------------------------
def response_text_if_file( a_text ):
    # --------------------------------------------------
    # treat response as raw (ie: not a file)
    # --------------------------------------------------
    ao_new_response = a_text
    # --------------------------------------------------
    # load the file if a file was passed
    # --------------------------------------------------
    l_file = Path(a_text).absolute()
    if l_file.exists():
        ao_new_response = l_file.read_text()
    # --------------------------------------------------
    # return response
    # --------------------------------------------------
    return ao_new_response
# ------------------------------------------------------------------------------
# create the response function
# ------------------------------------------------------------------------------
@G_App.route('/', defaults={'path': ''}, methods=["GET", "POST"])
@G_App.route('/<path:path>', methods=["GET", "POST"])
def catch_all(path):
    # --------------------------------------------------
    # global vars
    # --------------------------------------------------
    global G_Static_Response, G_Static_Status
    # --------------------------------------------------
    # return text we will send back in response -
    # defaults to static_response
    # --------------------------------------------------
    l_return_status = G_Static_Status
    l_return_text = G_Static_Response
    # --------------------------------------------------
    # upated the response if they sent a set reponse
    # header
    # --------------------------------------------------
    l_set_response = request.headers.get(G_SET_RESPONSE_HEADER)
    if l_set_response:
        G_Static_Response = response_text_if_file( l_set_response )
        l_return_text = G_Static_Response
    # --------------------------------------------------
    # return the response specified if they sent a
    # dynamic response header
    # --------------------------------------------------
    l_dynamic_response = request.headers.get(G_DYNAMIC_RESPONSE_HEADER)
    if l_dynamic_response:
        l_return_text = response_text_if_file( l_dynamic_response )
    # --------------------------------------------------
    # set response status if sent
    # --------------------------------------------------
    l_set_response_status = request.headers.get(G_SET_RESPONSE_STATUS_HEADER)
    if l_set_response_status:
        G_Static_Status = response_text_if_file( l_set_response_status )
        l_return_status = G_Static_Status
    # --------------------------------------------------
    # set dynamic response status if sent
    # --------------------------------------------------
    l_dynamic_response_status = request.headers.get(G_DYNAMIC_RESPONSE_STATUS_HEADER)
    if l_dynamic_response_status:
        l_return_status = response_text_if_file( l_dynamic_response_status )
    # --------------------------------------------------
    # create response object
    # --------------------------------------------------
    l_resp = Response(l_return_text, int(l_return_status))
    # --------------------------------------------------
    # special header - mirrior host from request if
    # found
    # --------------------------------------------------
    l_req_host = request.headers.get("host")
    if l_req_host: l_resp.headers["Host"] = l_req_host
    # --------------------------------------------------
    # mirror back any dev headers
    # --------------------------------------------------
    for i_name, i_value in request.headers.items():
        if i_name.lower().startswith('x-waf'):
            l_resp.headers[i_name] = i_value
    # --------------------------------------------------
    # return the response
    # --------------------------------------------------
    return l_resp
# ------------------------------------------------------------------------------
# run from terminal
# ------------------------------------------------------------------------------
if __name__ == '__main__':
    # ------------------------------------------------------
    # create arg parser to get possible flags
    # ------------------------------------------------------
    arg_parser = argparse.ArgumentParser(
        description="fake origin :D",
        usage="%(prog)s",
        epilog=""
    )
    # ------------------------------------------------------
    # args to file
    # ------------------------------------------------------
    arg_parser.add_argument(
        "-p",
        "--port",
        dest="port",
        help="The port for the origin to run on. (default 8080)",
        type=int,
        default=8080,
        required=False
    )
    arg_parser.add_argument(
        "-r",
        "--respond",
        dest="respond",
        help="static response for the server. loads text if given a file name",
        type=str,
        default="Hello :D\n",
        required=False
    )
    # ------------------------------------------------------
    # parse args
    # ------------------------------------------------------
    args = arg_parser.parse_args()
    # ------------------------------------------------------
    # load response if given in args
    # ------------------------------------------------------
    if args.respond != G_Static_Response:
        G_Static_Response = response_text_if_file(args.respond)
    # ------------------------------------------------------
    # start fake origin
    # ------------------------------------------------------
    G_App.run(port=args.port)