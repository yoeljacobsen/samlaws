## Instructions

* Make sure python3 is installed, preferably in a virtualenv
* Install the requirements: `pip install -r requirements.txt`
* Test

If using a virtual environment remmebr to `source <envdir>/bin/activate` first.

In order to test the pam_exec case:
`export PAM_USER=<user>`
`echo -n <password> | ./samlLab2.py`

In order to test the interactive case:
`unset PAM_EXEC`
`samlLab2.py`

