import os
import datetime
import logging
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import pexpect
import time
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError
import argparse
import warnings

#ignore warnings about slack api upload file api call
warnings.filterwarnings('ignore')


def revoke_user(username, ca_key_password):
    logging.info(f"Revoking certificate for {username}")
    revoke_process = pexpect.spawn('/etc/openvpn/EasyRSA/easyrsa revoke {}'.format(username))
    #revoke_process.expect("    Continue with revocation:")
    revoke_process.expect("Type the word 'yes' to continue, or any other input to abort.")
    time.sleep(1)  # Delay for 1 second
    revoke_process.sendline("yes")
    revoke_process.expect("Enter pass phrase for*")
    time.sleep(1)  # Delay for 1 second
    revoke_process.sendline(ca_key_password)
    revoke_process.expect(pexpect.EOF)

    # Generate CRL
    logging.info(f"Generating CRL")
    gen_crl_process = pexpect.spawn('/etc/openvpn/EasyRSA/easyrsa gen-crl')
    gen_crl_process.expect("Enter pass phrase for*")
    time.sleep(1)  # Delay for 1 second
    gen_crl_process.sendline(ca_key_password)
    gen_crl_process.expect(pexpect.EOF)

    try:
        copy_crl_process = pexpect.spawn('mv /etc/openvpn/EasyRSA/pki/crl.pem /etc/openvpn/crl_engineering_prod.pem')
        copy_crl_process.expect(pexpect.EOF)
        logging.info(f"Revoked certificate for {username} and updated CRL.")
    except subprocess.CalledProcessError as e:
        logging.exception(f"An error occurred copying crl: {e}")

#Function to check if a cert already exists
def check_for_cert(directory_path, file_name):
    # Get a list of all files in the directory
    files_in_directory = os.listdir(directory_path)
    # Check if the file_name exists in the list of files
    if file_name in files_in_directory:
        return True
    else:
        return False
        
# Function to send a message using the Slack API
def send_message(client, user_id, message):
    try:
        response = client.chat_postMessage(channel=user_id, text=message)
        if response["ok"]:
            logging.info("Message sent successfully to user " + user_id)
        else:
            logging.exception("Failed to send message:", response["error"])
    except SlackApiError as e:
        error_message = e.response['error']
        logging.exception(f"Failed to send message to user {user_id}: {error_message}")

def main():

    # Create an argument parser
    parser = argparse.ArgumentParser(description='OpenVPN Script')

    # Add a username argument
    parser.add_argument('--username', type=str, help='Provide the username)', required=True)

    # Add a ca_key_password argument
    parser.add_argument('--ca_key_password', type=str, help='Provide the password for the CA key)', required=True)

    # Add the slack token argument
    parser.add_argument('--slack_token', type=str, help='Provide the slack token', required=True)

    # Configure logging settings
    log_filename = '/var/log/openvpn/revoke_ovpn_cert.log'
    logging.basicConfig(filename=log_filename,
                    level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

    # Parse the command-line arguments
    args = parser.parse_args()
    logging.info(f"--------------------------------------------")
    logging.info(f"args.username {args.username}")
    logging.info(f"args.slack_token {args.slack_token}")
    logging.info(f"args.ca_key_password {args.ca_key_password}")

    #This is where all the certificates that have been created are stored
    certs_directory = "/etc/openvpn/EasyRSA/pki/issued"

    #This is where we store all the "ovpn" files that we give the end users for their devices
    ovpn_directory = "/etc/openvpn/EasyRSA/ovpn"

    current_year = datetime.datetime.now().year

    # Slack API token for OVPN Bot provided by --slack_token argument which is provided from ansible credential
    slack_token = args.slack_token
    client = WebClient(token=slack_token)

    #We want to log all renewals to the Slack #devops channel
    devops_channel_id = "C06D6E1QMFE"

    username = args.username
    ca_key_password = args.ca_key_password

    if check_for_cert(certs_directory, username + ".crt"):
         logging.info(f"Certificate exists!")
         logging.info(f"Calling revoke_certificate function")
         try:
            #Call the revoke_user function to revoke certificate
            revoke_user(username, ca_key_password)
            #If all of this worked without blowing up.. notify #devops that a new cert was sent to the user
            devops_channel_message = (f"Certificate revoked for " + username)
            logging.info("Sending \"Certificate revoked for user\" message to devops")
            send_message(client, devops_channel_id, devops_channel_message)
         except SlackApiError as e:
            error_message = e.response['error']
            logging.exception(f"Failed: {error_message}")
            devops_channel_message = (f"Exception: Could not revoke certificate for " + username)
            logging.info("Sending \"Could not revoke certificate\" message to \#devops")
            send_message(client, devops_channel_id, devops_channel_message)

    else:
        logging.info(f"The certificate does not exist in the directory.")
        print("Certificate does not exist!")
        #Exit script
        sys.exit('Certificate does not exist!')
        
if __name__ == "__main__":
    main()

