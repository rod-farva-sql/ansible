---
- name: Copy create_ovpn_cert file from local git repository on ansible server to ovpn server
  hosts: all
  tasks:
    - name: Copy file
      copy:
        src: "create_ovpn_cert.py"
        dest: "/etc/openvpn/EasyRSA/create_ovpn_cert.py"
      register: download_output

    - name: Debug script output
      debug:
        var: download_output

        
- name: Execute the create_ovpn_cert
  hosts: all
  become: yes
  tasks:
      - name: Execute the script
        ansible.builtin.command:
          cmd: "python3 /etc/openvpn/EasyRSA/create_ovpn_cert.py --username {{ username }} --is_mobile {{ is_mobile }} --send_slack_message {{ send_slack_message }} --slack_token {{ slack_token }} --ca_key_password {{ ca_key_password }}"
          chdir: /etc/openvpn/EasyRSA
        register: script_output

      - name: Debug script output
        debug:
          var: script_output
