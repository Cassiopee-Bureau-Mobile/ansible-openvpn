# This Repo is only for private use because it fit with specific needs.

I made some changes to the original repo to fit my needs. I will try to keep it up to date with the original repo.

I also remove the `sync_clients.yml` playbook because I don't need it.

I add `become` to the playbooks because I run it on a fresh installed system.

# ansible-openvpn

Ansible role and playbooks for installing openvpn and managing clients.

This is a fork of [ansible-openvpn-hardened](https://github.com/bau-sec/ansible-openvpn-hardened).

ansible-openvpn-hardened has a lot of cool features when it comes to openvpn and a nice approach to managing client keys.
It is however more geared towards configuring a complete system. It is basically setting up a secured, hardened box that runs openvpn from scratch. So it is not really possible to only use parts of it or plug this into one of your existing hosts or.

This project is about setting up openvpn on any kind of system and touching only the parts that are necessary by making as few as possible assumptions about your system / not messing with your current configuration while keeping almost all the cool features found in ansible-openvpn-hardened.

Features kept:

- setting up a OpenVPN PKI using easyrsa3 with certificate revokation, DH parameters and HMAC
- generates [multiple OpenVPN client configurations](#Distributing-key-files)
- support for [certificate signing request](#Adding-clients-using-a-CSR)
- convenient [client management](#Adding-clients) via ansible playbooks, e.g. will [fetch](http://docs.ansible.com/ansible/latest/modules/fetch_module.html) client config files
- use only TLS ciphers that implement perfect forward secrecy
- OpenVPN configuration aims to enhance security, e.g. use of `tls-auth`, `verify-x509-name` or `push block-outside-dns`
- CA password is not stored on the OpenVPN host

Features this project adds to that:

- support for running on and managing multiple hosts at once
- support for names (CA, clients) with whitespace
- made more things configurable, e.g. setting the DN_mode or the OpenVPN CN or adding arbitrary OpenVPN configuration to server and/or clients

Things I stripped from ansible-openvpn-hardened, because they are not directly related to OpenVPN or might not be desired by users who run this on existing systems. So this project wil **NOT**:

- upgrade all packages and install software to periodically update them
- remove any of the installed packages
- install dnsmasq
- modify the iptables firewall rules
- reboot after `install.yml` playbook is finished
- install auditd, aide or any other software used for hardening or auditing

Features still to come:

- more configuration options for openvpn
- IPv6 support

However I also had to switch back to running openvpn as a privileged user for now because I ran into too many problems with that, might be changed in the future.

## Supported Targets

The following Linux distros are tested:

- CentOS 7.2
- Ubuntu 16.04
- Debian 8.7

Other distros and versions may work too. If support for another distro is desired, submit an issue ticket. Pull requests are always welcome.

# Quick start

Copy the sample Ansible inventory and variables to edit for your setup. (I will use `my_project` as an example for the rest of this documentation)

    cp -r inventories/sample inventories/my_project

Edit the inventory hosts (`hosts.ini`) to target your desired host. You can also change the [configuration variables](#configuration-variables) in (`group_vars/all.yml`), the defaults are however sufficient for this quickstart example.
It is also possible to [target multiple hosts each using different variables](#targeting-multiple-hosts).

OpenVPN requires some firewall rules to forward packets. By default firewall **NO** rules will be written/altered.  
However you can set `load_iptables_rules` to `true` and a [generated script](./playbooks/roles/openvpn/templates/etc_iptables_rules.v4.j2), that you can find at `/etc/openvpn/openvpn_iptables_rules.sh` on the host (after installation finished) will load the minimum required rules into ip(v4)tables. If you opt to not do this you can set the firewall rules by hand. OpenVPN will need at least the `MASQUERADE` rule from that script to work.

Run the install playbook

    ansible-playbook -i inventories/my_project/hosts.ini playbooks/install.yml

The OpenVPN server is now up and running. Time to add some clients.

## Adding clients manually

To add clients, you can also run the `add_clients.yml` playbook. It needs a list named `clients_to_add`, see [the file used for the tests](./test/ansible-vars/02_add_clients.yml) on how this looks like.

    ansible-playbook playbooks/add_clients.yml -i inventories/my_project/hosts.ini -e "@test/ansible-vars/02_add_clients.yml"

The credentials will be in the `fetched_creds/` directory after the playbook finished succesfully. Try connecting to the OpenVPN server:

    cd fetched_creds/[inventory_hostname]/[client name]/
    openvpn [client name]-pki-embedded.ovpn

You'll be prompted for the private key passphrase, this is stored in a file ending in `.txt` in the client directory you just entered in the step above.

### Distributing key files

Three different OpenVPN configuration files are provided because OpenVPN clients on different platforms have different requirements for how the PKI information is referenced by the .ovpn file. This is just for convenience. All the configuration information and PKI info is the same, it's just formatted differently to support different OpenVPN clients.

All those files are stored in the `fetched_creds/[inventory_hostname]/[client name]/data` directory.

- **PKI embedded** - the easiest if your client supports it. Only one file required and all the PKI information is embedded.
  - `XYZ-pki-embedded.ovpn`
- **PKCS#12** - all the PKI information is stored in the PKCS#12 file and referenced by the config. This can be more secure on Android where the OS can store the information in the PKCS#12 file in hardware backed encrypted storage.
  - `XYZ-pkcs.ovpn`
  - `XYZ.p12`
- **PKI files** - if the above two fail, all clients should support this. All of the PKI information is stored in separate files and referenced by the config.
  - `XYZ-pki-files.ovpn` - OpenVPN configuration
  - `ca.pem` - CA certificate
  - `XYZ.key` - client private key
  - `XYZ.pem` - client certificate

You can find the embedded openvpn config under `fetched_creds/[inventory_hostname]/[client name]/[client_name].ovpn` directory.

### Private key passphrases

Entering a pass phrase every time the client is started can be annoying.

The encryption of the private key as been removed to delete the need to enter a passphrase every time the client is started.

### Adding clients using a CSR

Clients can also be added using a certificate signing request, CSR. This is useful if you intend to use keys generated and stored in a TPM. Generating the CSR will depend on your hardware, OS, TPM software, etc. If you're interested in this feature, you can probably figure this out (though [`.travis.yml`](.travis.yml) has an example of generating a CSR with _openssl_). This [blog post](https://qistoph.blogspot.nl/2015/12/tpm-authentication-in-openvpn-and-putty.html) shows how to create private key stored in a TPM and generate a CSR on Windows.

The variable `csr_path` specifies the local path to the CSR. `cn` specifies the common name specified when the CSR was created.

    ansible-playbook -e "csr_path=~/test.csr cn=test@domain.com" playbooks/add_clients.yml

This will generate the client's signed certificate and put it in `fetched_creds/[server ip]/[cn]/` as well as a nearly complete `.ovpn` client configuration file. You'll need to add references to or embed your private key and signed certificate. This will vary based on how your private key is stored. If your following the guide in the blog post mentioned above you'd do this using the OpenVPN option `cryptoapicert`.

## Targeting multiple hosts

It is possible to not only target multiple hosts but also use different groups and apply certain configuration variables to that group only. An example:

Consider this `hosts.ini` inventory:

```
[production]
bastion-prod-us-east-1
bastion-prod-us-east-2

[qa]
bastion-qa

[openvpn:children]
production
qa
```

You can now create a file `production.yml` in `group_vars/`:

```
openvpn_key_country:  "US"
openvpn_key_province: "Ohio"
openvpn_key_city: "Cleveland"
openvpn_key_org: "FOOBAR CORPORATION"
openvpn_key_ou: "Operations"
openvpn_key_email: "foobar@example.com"
```

This configuration will now be applied to hosts in the `production` group only and will override variables from the `all.yml`.  
You can even do this on a per-host level, which will override group-level variables.  
E.g. create a file `host_vars/bastion-prod-us-east-1.yml`:

```
openvpn_key_ou: "Operations Unit B"
```

Further reading: [Ansible variable documentation, especially section: "Precedence"](http://docs.ansible.com/ansible/latest/user_guide/playbooks_variables.html).

This also comes in handy when managing clients with the `sync_clients.yml` playbook because you can then configure which clients are valid on a per-host or per-group basis.

## Revoke client access manually

**NOTE**: Once you revoke a client, it is NOT possible to make it valid again, so I suggest using somewhat unique names as `valid_clients`.

To revoke clients access, you can run the `revoke_clients.yml` playbook. It needs a list named `clients_to_revoke`, see [the file used for the tests](./test/ansible-vars/03_revoke_clients.yml) on how this looks like.

    ansible-playbook playbooks/revoke_clients.yml -e "@test/ansible-vars/03_revoke_clients.yml"

# Managing the OpenVPN server

## Configuration variables

There is documentation on the most important variables in [all.yml](./inventories/sample/group_vars/all.yml).

### OpenVPN server configuration

For the full server configuration, see [`etc_openvpn_server.conf.j2`](playbooks/roles/openvpn/templates/etc_openvpn_server.conf.j2)

- `tls-auth` aids in mitigating risk of denial-of-service attacks. Additionally, when combined with usage of UDP at the transport layer (the default configuration used by _ansible-openvpn-hardened_), it complicates attempts to port scan the OpenVPN server because any unsigned packets can be immediately dropped without sending anything back to the scanner.

  - From the [OpenVPN hardening guide](https://community.openvpn.net/openvpn/wiki/Hardening):

    > The tls-auth option uses a static pre-shared key (PSK) that must be generated in advance and shared among all peers. This features adds "extra protection" to the TLS channel by requiring that incoming packets have a valid signature generated using the PSK key... The primary benefit is that an unauthenticated client cannot cause the same CPU/crypto load against a server as the junk traffic can be dropped much sooner. This can aid in mitigating denial-of-service attempts.

- `push block-outside-dns` used by OpenVPN server to fix a potential dns leak on Windows 10
  - See https://community.openvpn.net/openvpn/ticket/605
- `tls-cipher` limits allowable TLS ciphers to a subset that supports [**perfect forward secrecy**](https://en.wikipedia.org/wiki/Forward_secrecy)

  - From wikipedia:

  > Forward secrecy protects past sessions against future compromises of secret keys or passwords. If forward secrecy is used, encrypted communications and sessions recorded in the past cannot be retrieved and decrypted should long-term secret keys or passwords be compromised in the future, even if the adversary actively interfered.

- `cipher` set to `AES-256-CBC` by default
- `2048` bit RSA key size by default.
  - This can be increased to `4096` by changing `openvpn_key_size` in [`defaults/main.yml`](playbooks/roles/openvpn/defaults/main.yml) if you don't mind extra processing time. Consensus seems to be that 2048 is sufficient for all but the most sensitive data.

### OpenVPN client configuration

For the full client configuration, see [`client_common.ovpn.j2`](playbooks/roles/add_clients/templates/client_common.ovpn.j2)

- `verify-x509-name` prevents MitM attacks by verifying the server name in the supplied certificate matches the clients configuration.
- `persist-tun` prevents the traffic from leaking out over the default interface during interruptions and reconnection attempts by keeping the tun device up until connectivity is restored.

### PKI

- [easy-rsa](https://github.com/OpenVPN/easy-rsa) is used to manage the public key infrastructure.
- OpenVPN is configured to read the CRL generated by _easy-rsa_ so that a single client's access can be revoked without having to reissue credentials to all of the clients.
- The private keys generated for the clients and CA are all protected with a randomly generated passphrase to facilitate secure distribution to client devices.

### Firewall

OpenVPN requires some firewall rules to forward packets.  
By default **NO** firewall rules will be written/altered.  
However you can set `load_iptables_rules` to `true` and a [generated script](./playbooks/roles/openvpn/templates/etc_iptables_rules.v4.j2), that you can find at `/etc/openvpn/openvpn_iptables_rules.sh` on the host (after installation finished) will load the minimum required rules into ip(v4)tables. If you opt to not do this you can set the firewall rules by hand. OpenVPN will need at least the `MASQUERADE` rule from that script.

### Credentials (CA password)

Credentials are generated during the install process and are saved as yml formatted files in the Ansible file hierarchy so they can be used without requiring the playbook caller to take any action. The locations are below.

- CA Private key passphrase - saved in `inventories/my_project/host_vars/[inventory_hostname].yml`

# Contributing

Contributions via pull request, feedback, bug reports are all welcome.
