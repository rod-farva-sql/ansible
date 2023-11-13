#!/user/bin/python3

import os
import datetime
import logging
import pexpect
import time
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError
import sys
import argparse
import warnings
import ast

warnings.filterwarnings('ignore')

def create_certificate(new_cert_username, is_mobile, ca_key_password):
    logging.info(f"Creating certificate for {new_cert_username}")
    gen_req_process = pexpect.spawn('/etc/openvpn/EasyRSA/easyrsa gen-req {} nopass'.format(new_cert_username))
    gen_req_process.expect("Common Name*")
    gen_req_process.sendline("\r")
    gen_req_process.expect(pexpect.EOF)
    sign_req_process = pexpect.spawn('/etc/openvpn/EasyRSA/easyrsa sign-req client {}'.format(new_cert_username))
    sign_req_process.expect("Confirm request details*")
    sign_req_process.sendline("yes")
    sign_req_process.expect("Enter pass phrase for*")
    time.sleep(1) #need to have a slight pause
    sign_req_process.sendline(ca_key_password)
    sign_req_process.expect(pexpect.EOF)

    copy_key_process = pexpect.spawn('cp pki/private/{}.key /etc/openvpn/certs'.format(new_cert_username))
    copy_key_process.expect(pexpect.EOF)

    crt_destination = '/etc/openvpn/certs/{}.key'.format(new_cert_username)
    if os.path.exists(crt_destination):
        logging.info("Certificate .key copied successfully: %s", crt_destination)
    else:
        logging.exception("Certificate .key copy failed.")

    copy_crt_process = pexpect.spawn('cp pki/issued/{}.crt /etc/openvpn/certs'.format(new_cert_username))
    copy_crt_process.expect(pexpect.EOF)

    crt_destination = '/etc/openvpn/certs/{}.crt'.format(new_cert_username)
    if os.path.exists(crt_destination):
        logging.info("Certificate .crt copied successfully: %s", crt_destination)
    else:
        logging.exception("Certificate .crt copy failed.")

def generate_ovpn_file(new_cert_username, is_mobile, ca_key_password):
    logging.info("Generating ovpn file")
    logging.info(f'Extracted username: {new_cert_username}')
    template_file_path = '/etc/openvpn/EasyRSA/ovpn_template.txt'
    ovpn_file_path = f'/etc/openvpn/EasyRSA/ovpn/eng-{new_cert_username}.ovpn'
    crt_file_path = f'/etc/openvpn/certs/{new_cert_username}.crt'
    key_file_path = f'/etc/openvpn/certs/{new_cert_username}.key'

    with open(template_file_path, 'r') as template_file:
        template_content = template_file.read()

    ovpn_content = template_content.replace('flastname', new_cert_username)

    with open(ovpn_file_path, 'w') as ovpn_file:
        ovpn_file.write(ovpn_content)

    with open(crt_file_path, 'r') as source_file:
        content = source_file.read()

    last_cert_start = content.rfind("-----BEGIN CERTIFICATE-----")
    extracted_content = content[last_cert_start:]

    with open(ovpn_file_path, 'a') as target_file:
        target_file.write(extracted_content)
        target_file.write('</cert>\n<key>\n')

        with open(key_file_path, 'r') as key_file:
             key_content = key_file.read()
             target_file.write(key_content)

        target_file.write('</key>')

    logging.info(f'Generated {ovpn_file_path} with username: {new_cert_username}')

# Function to send a message using the Slack API
def send_message(client, user_id, message):
    try:
        response = client.chat_postMessage(channel=user_id, text=message)
        if response["ok"]:
            logging.info("Message sent successfully")
        else:
            logging.exception("Failed to send message: %s", response["error"])
    except SlackApiError as e:
        error_message = e.response['error']
        logging.exception(f"Failed to send message to user {user_id}: {error_message}")

# Function to send a file using the Slack API
def send_file(client, user_id, file_path, filename):
    try:
        with open(file_path, 'rb') as file_content:
            response = client.files_upload(
                channels=user_id,
                file=file_content,
                filename=filename,
            )
            if response['ok']:
                logging.info(f"%s sent successfully to user %s", filename, user_id)
            else:
                logging.exception("%s failed to send file to user %s: %s", filename, user_id, response['error']['msg'])
    except SlackApiError as e:
        error_message = e.response['error']
        logging.exception(f"Failed to send file to user {user_id}: {error_message}")


#Function to check if a cert already exists
def check_for_cert(directory_path, file_name):
    # Get a list of all files in the directory
    files_in_directory = os.listdir(directory_path)
    # Check if the file_name exists in the list of files
    if file_name in files_in_directory:
        return True
    else:
        return False

#Function to revoke a certificate
def revoke_certificate(cert_name, ca_key_password):
    logging.info(f"Revoking cert for {cert_name}") 
    # Run the 'easyrsa revoke' command and accept the default common name prompt
    revoke_process = pexpect.spawn("/etc/openvpn/EasyRSA/easyrsa revoke {}".format(cert_name), timeout=10)
    revoke_process.expect("Continue with revocation:*")
    revoke_process.sendline("yes")
    revoke_process.expect("Enter pass phrase for /etc/openvpn/EasyRSA/pki/private/ca.key:*")
    time.sleep(1) #need to have a slight pause or it will crash
    revoke_process.sendline(ca_key_password)
    revoke_process.expect(pexpect.EOF)

    logging.info("Generating new CRL")
    revoke_process = pexpect.spawn("/etc/openvpn/EasyRSA/easyrsa gen-crl", timeout=10)
    revoke_process.expect("Enter pass phrase for /etc/openvpn/EasyRSA/pki/private/ca.key:*")
    time.sleep(1)
    revoke_process.sendline(ca_key_password)
    revoke_process.expect(pexpect.EOF)

    # Move the CRL file
    mv_process = pexpect.spawn("mv /etc/openvpn/EasyRSA/pki/crl.pem /etc/openvpn/crl_engineering_prod.pem", timeout=10)
    mv_process.expect(pexpect.EOF)




def main():

    certs_directory = "/etc/openvpn/EasyRSA/pki/issued"

    # Configure logging settings
    log_filename = '/var/log/openvpn/create_ovpn_cert.log'
    logging.basicConfig(filename=log_filename,
                    level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')



    # Create an argument parser
    parser = argparse.ArgumentParser(description='OpenVPN Script')

    # Add a username argument
    parser.add_argument('--username', help='username', required=True)

    # Add a -slack flag
    #parser.add_argument('-slack', action='store_true', help='Send the message to the user over Slack')

    # Add a -mobile flag
    #parser.add_argument('-mobile', action='store_true', help='Append "-mobile" to the username')

    # Add an is_mobile argument
    parser.add_argument('--is_mobile', type=str, help='Create a mobile certificate (True/False)', required=True)

    # Add a send_slack_message argument
    parser.add_argument('--send_slack_message', type=str, help='Send a Slack message (True/False)', required=True)

    # Add a CA_KEY_PASSWORD argument
    parser.add_argument('--ca_key_password', type=str, help='Provide the password for the CA key)', required=True)

    # Add the slack token argument
    parser.add_argument('--slack_token', type=str, help='Provide the slack token', required=True)

    # Parse the command-line arguments
    args = parser.parse_args()
    logging.info(f"--------------------------------------------")
    logging.info(f"args.username {args.username}")
    logging.info(f"args.slack {args.send_slack_message}")
    logging.info(f"args.mobile {args.is_mobile}")
    logging.info(f"args.slack_token {args.slack_token}")
    logging.info(f"args.ca_key_password {args.ca_key_password}")

    username = args.username
    send_slack_message = ast.literal_eval(args.send_slack_message)
    is_mobile = ast.literal_eval(args.is_mobile)
    ca_key_password = args.ca_key_password

    # Replace 'YOUR_TOKEN_HERE' with your actual Slack API token
    slack_token = args.slack_token 
    client = WebClient(token=slack_token)

    #We want to log all creations to the Slack #devops channel
    devops_channel_id = "C063P708JRE"
    
    ovpn_directory = "/etc/openvpn/EasyRSA/ovpn"
    current_year = datetime.datetime.now().year

    if username:
        if is_mobile:
            new_cert_username = f"{username}-mobile"
        else:
            new_cert_username = username

        new_cert_username = f"{new_cert_username}-{current_year}"

        logging.info(f"Checking if certificate already exists")

        if check_for_cert(certs_directory, new_cert_username + ".crt"):
            logging.info(f"Certificate already exists!")
            #Exit script
            #sys.exit('Certificate already exists!')
            logging.info(f"Calling revoke_certificate function")
            revoke_certificate(new_cert_username, ca_key_password)

        else:
            logging.info(f"The certificate does not exist in the directory.")
        logging.info(f"Calling create_certificate function")
        create_certificate(new_cert_username, is_mobile, ca_key_password)
        logging.info(f"Calling generate_ovpn_file function")
        generate_ovpn_file(new_cert_username, is_mobile, ca_key_password)

        if send_slack_message:
            # Send the message to the user over Slack
            ##message = "Your OpenVPN certificate has been renewed."
            ##send_message(client, user_id, message)
                logging.info(f"Sending slack message")
                try:
                    user_email = f"{username}@gmail.com"
                    response = client.users_lookupByEmail(email=user_email)
                    user_id = response['user']['id']
                    logging.info(f"User with email {user_email} has ID: {user_id}")
                except SlackApiError as e:
                    error_message = e.response['error']
                    logging.exception(f"Failed to look up user with email {user_email}: {error_message}")

                ovpn_filename = f'eng-{new_cert_username}.ovpn'

                if is_mobile:
                     message = ("Hello!\nThis is the XXX OpenVPN Bot! Your 'Mobile' VPN certificate has been generated.  We have posted instructions on the Confluence wiki at https://XXXXX.XXXXXXXX.net/wiki/spaces/XXXXXXXXXXXXXXXX/pages/2501410834/How+to+replace+your+OpenVPN+Certificate+Renewals to help guide you through the necessary steps installing the certificate.\n\nYou should receive a certificate named \"" + ovpn_filename +"\".  Please follow the 'Android' or 'IPhone' instructions appropriate for the mobile device you own.\n\nIf you get stuck or encounter error messages, please open an issue in the CLOUDOPS Jira project so we can visit with you to resolve the problem.\nThank you!\nOpenVPN Bot")
                else:
                    message = ("Hello!\nThis is the XXX OpenVPN Bot!  Your 'PC' VPN certificate has been generated!  We have posted instructions on the Confluence wiki at https://XXXXX.XXXXXXXX.net/wiki/spaces/XXXXXXXXXXXXXXXX/pages/2501410834/How+to+replace+your+OpenVPN+Certificate+Renewals to help guide you through the necessary steps.\n\nYou should receive a certificate named \"" + ovpn_filename +"\".  Please follow the 'Windows PC and Mac Laptop' instructions to update your laptop certificate.\n\nIf you get stuck or encounter error messages, please open an issue in the CLOUDOPS Jira project so we can visit with you to resolve the problem.\nThank you!\nOpenVPN Bot")

                send_message(client, user_id, message)
                send_file(client, user_id, os.path.join(ovpn_directory, ovpn_filename), ovpn_filename)
                devops_channel_message = (f"Certificate created for " + username)
                send_message(client, devops_channel_id, devops_channel_message)

if __name__ == "__main__":
    main()
