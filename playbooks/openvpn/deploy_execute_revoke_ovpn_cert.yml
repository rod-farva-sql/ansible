---
- name: Download revoke_ovpn_cert file from GitHub
  hosts: all
  tasks:
    - name: Download file from GitHub
      get_url:
        url: "https://raw.githubusercontent.com/rod-farva-sql/ansible/main/revoke_ovpn_cert.py"
        dest: "/etc/openvpn/EasyRSA/revoke_ovpn_cert.py"
      register: download_output

    - name: Debug script output
      debug:
        var: download_output.stdout

        
- name: Execute the revoke_ovpn_cert script
  hosts: all
  become: yes
  tasks:
      - name: Execute the script
        ansible.builtin.shell:
          cmd: "python3 /etc/openvpn/EasyRSA/revoke_ovpn_cert.py --slack_token {{ slack_token }} --ca_key_password {{ ca_key_password }}"
          chdir: /etc/openvpn/EasyRSA
        register: script_output

      - name: Debug script output
        debug:
          var: script_output.stdout
