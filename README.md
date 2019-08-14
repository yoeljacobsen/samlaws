## Instructions

Note - Need more documentation to support selinux.
At the moment, simply `setenforce 0`

* Make sure python3 is installed, preferably in a virtualenv
* Install the requirements: `pip install -r requirements.txt`
* Test

If using a virtual environment remmebr to `source <envdir>/bin/activate` first.

In order to test the pam_exec case:
* `export PAM_USER=<user>`
* `echo -n <password> | ./samlLab2.py`

In order to test the interactive case:
* `unset PAM_EXEC`
* `samlLab2.py`

To activate the pam_exec usage, add the following lines to /etc/pam.d/sshd:

```
# Support for AWS temporary credentials
auth	   optional     pam_exec.so debug expose_authtok log=/tmp/pam_exec.log /home/labs/testing/eldara/samlaws/pam_helper.sh
```
