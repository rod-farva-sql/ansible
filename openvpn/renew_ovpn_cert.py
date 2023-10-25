import os
import datetime
import logging
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import pexpect
import time
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError
import warnings

#ignore warnings about slack api upload file api call
warnings.filterwarnings('ignore')

def check_certificate_expiration(cert_path, days_threshold):
    with open(cert_path, 'rb') as cert_file:
        cert_data = cert_file.read()
    cert_filename = os.path.basename(cert_path)
    username, is_mobile, year = parse_certificate_filename(cert_filename)
    logging.info(f"Checking cert expiration for {cert_filename}")
    cert = x509.load_pem_x509_certificate(cert_data, default_backend())
    expiration_date = cert.not_valid_after
    remaining_days = (expiration_date - datetime.datetime.utcnow()).days

    if remaining_days <= days_threshold:
        logging.info(f"Certificate {cert_filename} expires in {remaining_days} days.")
        return username, is_mobile, year
    else:
        return None, False, None


def parse_certificate_filename(cert_filename):
    base_filename = cert_filename.replace('.crt', '')
    is_mobile = "-mobile" in base_filename
    parts = base_filename.split('-')
    if is_mobile:
        parts.remove("mobile")
    username = parts[0]
    year = None
    for part in parts[1:]:
        if part.isdigit() and len(part) == 4:
            year = part
            break

    logging.info(f"Username:  {username}")
    logging.info(f"Is Mobile:  {is_mobile}")
    logging.info(f"Year:  {year}")
    return username, is_mobile, year

def renew_certificate(new_cert_username, is_mobile, ca_key_password):
    logging.info(f"Renewing certificate for {new_cert_username}")
    gen_req_process = pexpect.spawn('/etc/openvpn/EasyRSA/easyrsa gen-req {} nopass'.format(new_cert_username))
    gen_req_process.expect("Common Name*")
    gen_req_process.sendline("\r")
    gen_req_process.expect(pexpect.EOF)
    sign_req_process = pexpect.spawn('/etc/openvpn/EasyRSA/easyrsa sign-req client {}'.format(new_cert_username))
    sign_req_process.expect("Confirm request details*")
    sign_req_process.sendline("yes")
    sign_req_process.expect("Enter pass phrase for*")
    time.sleep(1)  #need to have a slight pause
    sign_req_process.sendline(ca_key_password)
    sign_req_process.expect(pexpect.EOF)

    copy_key_process = pexpect.spawn('cp pki/private/{}.key /etc/openvpn/certs'.format(new_cert_username))
    copy_key_process.expect(pexpect.EOF)

    crt_destination = '/etc/openvpn/certs/{}.key'.format(new_cert_username)
    if os.path.exists(crt_destination):
        logging.info("Certificate .key copied successfully: " + crt_destination)
    else:
        logging.exception("Certificate .key copy failed.")

    copy_crt_process = pexpect.spawn('cp pki/issued/{}.crt /etc/openvpn/certs'.format(new_cert_username))
    copy_crt_process.expect(pexpect.EOF)

    crt_destination = '/etc/openvpn/certs/{}.crt'.format(new_cert_username)
    if os.path.exists(crt_destination):
        logging.info("Certificate .crt copied successfully: " + crt_destination)
    else:
        logging.exception("Certificate .crt copy failed.")

def generate_ovpn_file(new_cert_username, is_mobile):
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


def revoke_user(username, ca_key_password):
    logging.info(f"Revoking certificate for {username}")
    revoke_process = pexpect.spawn('/etc/openvpn/EasyRSA/easyrsa revoke {}'.format(username))
    revoke_process.expect("    Continue with revocation:")
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


# Function to send a message using the Slack API
def send_message(client, user_id, message):
    try:
        response = client.chat_postMessagetoken(channel=user_id, text=message)
        if response["ok"]:
            logging.info("Message sent successfully to user " + user_id)
        else:
            logging.exception("Failed to send message:", response["error"])
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
                logging.info(f"{filename} sent successfully to user {user_id}")
            else:
                logging.exception(f"{filename} failed to send file to user {user_id}: {response['error']['msg']}")
    except SlackApiError as e:
        error_message = e.response['error']
        logging.exception(f"Failed to send file to user {user_id}: {error_message}")

# Function to lookup the slack user_id from the email address
def lookup_user_id_by_email(client, user_email):
    try:
        response = client.users_lookupByEmail(email=user_email)
        user_id = response['user']['id']
        logging.info(f"User with email {user_email} has ID: {user_id}")
        return user_id
    except SlackApiError as e:
        error_message = e.response['error']
        logging.exception(f"Failed to look up user with email {user_email}: {error_message}")
        return None


def main():

    # Create an argument parser
    parser = argparse.ArgumentParser(description='OpenVPN Script')

    # Add a ca_key_password argument
    parser.add_argument('--ca_key_password', type=str, help='Provide the password for the CA key)', required=True)

    # Add the slack token argument
    parser.add_argument('--slack_token', type=str, help='Provide the slack token', required=True)

    # Configure logging settings
    log_filename = '/var/log/openvpn/openvpnbot2.log'
    logging.basicConfig(filename=log_filename,
                    level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

    # Parse the command-line arguments
    args = parser.parse_args()
    logging.info(f"--------------------------------------------")
    logging.info(f"args.slack_token {args.slack_token}")
    logging.info(f"args.ca_key_password {args.ca_key_password}")

    #This is where all the certificates that have been created are stored
    certs_directory = "/etc/openvpn/EasyRSA/pki/issued"

    #This is where we store all the "ovpn" files that we give the end users for their devices
    ovpn_directory = "/etc/openvpn/EasyRSA/ovpn"

    #How many days left in the certificate expiration before we renew
    days_threshold = 824

    current_year = datetime.datetime.now().year

    # Slack API token for OVPN Bot provided by --slack_token argument which is provided from ansible credential
    slack_token = args.slack_token

    #We want to log all renewals to the Slack #devops channel
    devops_channel_id = "C8QPUH63S"


    #Lets begin by looping through all the certs to see how old they are and to look for any that are going to expire in X days (X being "days_threshold")
    for filename in os.listdir(certs_directory):
        #So we are going to check for any files that end in .crt but we don't want to touch the "server.crt"
        if filename.endswith(".crt") and "server.crt" not in filename:
            logging.info("---------------------------------------------------")
            logging.info(f"Filename: " + filename)
            cert_path = os.path.join(certs_directory, filename)
            username, is_mobile, year = check_certificate_expiration(cert_path, days_threshold)

            if username:
                new_cert_username = f"{username}-{current_year}"
                if is_mobile:
                    new_cert_username = f"{username}-mobile-{current_year}"
                if is_mobile:
                    username_with_mobile = f"{username}-mobile"
                else:
                    username_with_mobile = username
                if year:
                    username_with_mobile= f"{username_with_mobile}-{year}"

                user_email = f"{username}@fanthreesixty.com"
                user_id = lookup_user_id_by_email(client, user_email)

                if user_id is not None:
                   try:
                     #First we need to revoke the current certificate that is getting ready to expire
                     revoke_user(username_with_mobile)
                     #Next we need to renew/generate a new certificate
                     renew_certificate(new_cert_username, is_mobile)
                     #Now we need to take the current cert and add the ovpn specific connection information etc..
                     generate_ovpn_file(new_cert_username, is_mobile)
                     ovpn_filename = f'eng-{new_cert_username}.ovpn'

                     #The default message sent to a user for a non mobile device
                     message = ("Hello!\nThis is the OpenVPN Bot!  Your 'PC' VPN certificate has expired!  We have posted instructions on the Confluence wiki at https://xxx.xxxx.xxx")

                     if is_mobile:
                          message = ("Hello!\nThis is the OpenVPN Bot!  Your 'Mobile' VPN certificate has expired!  We have posted instructions on the Confluence wiki at https://xxx.xxxx.xxx")

                     logging.info("Sending message to " + user_id)
                     #Now we are going to send the above message to the end user over slack
                     send_message(client, user_id, message)
                     logging.info("Sending " + ovpn_filename + " to " + user_id)
                     #Now we will send the "ovpn" file to the end user over slack
                     send_file(client, user_id, os.path.join(ovpn_directory, ovpn_filename), ovpn_filename)

                     #If all of this worked without blowing up.. notify #devops that a new cert was sent to the user
                     devops_channel_message = (f"Certificate " + ovpn_filename + " sent to " + username)
                     logging.info("Sending \"Certificate sent to user\" message to devops")
                     #send_message(client, devops_channel_id, devops_channel_message)
                   except SlackApiError as e:
                     error_message = e.response['error']
                     logging.exception(f"Failed to look up user with email {user_email}: {error_message}")
                     devops_channel_message = (f"Error: Could not renew certificate for " + filename)
                     logging.info("Sending \"Could not renew certificate\" message to \#devops")
                     send_message(client, devops_channel_id, devops_channel_message)
                else:
                     logging.exception("No user_id found for " + user_email)
                     devops_channel_message = (f"Error: Could not find user_id for " + username)
                     logging.info("Sending \"Could not find user_id\" message to \#devops")
                     send_message(client, devops_channel_id, devops_channel_message)


if __name__ == "__main__":
    main()

