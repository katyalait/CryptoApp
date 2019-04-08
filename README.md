# CryptoApp
Small web-app to encrypt files uploaded to google drive

Instructions to install:
1. Create a virtualenv on your desktop and clone the git into this.
2. Install the pip-wheel by using the command `pip install -r requirements.txt` and if you are using Python3+ then `pip3 install -r requirements.txt`
3. Open terminal in the app folder and run your python environment.
4. Type the following into the command prompt: `>>>from main import db` followed by `>>>db.create_all()` and finally by `>>>db.exit()`.
5. This just set up the required packages and the database, assuming you have SQL enabled. 
6. Run the app by calling `python main.py` or `python3 main.py` and opening [127.0.0.1:8080](http://127.0.0.1:8080) in your browser.
