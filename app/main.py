import os, random, sys, io
from werkzeug.utils import secure_filename
import json, requests, flask
from flask import request, render_template, flash, redirect,  url_for
import google.oauth2.credentials, google_auth_oauthlib.flow, googleapiclient.discovery
from apiclient.http import MediaFileUpload, MediaIoBaseDownload
from apiclient import http
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate



basedir = os.path.abspath(os.path.dirname(__file__))
signed_in_user = "guest"

SQLALCHEMY_TRACK_MODIFICATIONS = False
ENCRYPTED_FOLDER = 'encrypted/'
UPLOAD_FOLDER = 'uploads/'
DOWNLOAD_FOLDER = 'downloads/'
TEMPLATES = 'templates/'

app = flask.Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['ENCRYPTED_FOLDER'] = ENCRYPTED_FOLDER
app.config['DOWNLOAD_FOLDER'] = DOWNLOAD_FOLDER
app.config['TEMPLATES'] = TEMPLATES
app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:////" + os.path.join(basedir, 'app.db')

ALLOWED_EXTENSIONS = set(['txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'pdf', 'docx', 'csv', 'ppt'])
CLIENT_SECRETS_FILE = "client_secret_NNN.json"

SCOPES = ['https://www.googleapis.com/auth/drive', 'https://www.googleapis.com/auth/drive.appdata', 'https://www.googleapis.com/auth/drive.file']
API_SERVICE_NAME = 'drive'
API_VERSION = 'v3'
app.secret_key = '\xfd{H\xe5<\x95\xf9\xe3\x96.5\xd1\x01O<!\xd5\xa2\xa0\x9fR"\xa1\xa8'
db = SQLAlchemy(app)

class GroupEntry(db.Model):
    group_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(80), nullable=False)

    def __repr__(self):
        returnval = "<Group Entry: " + str(self.user_id) + str(self.group_id) + " >"
        return returnval

class Group(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    creator = db.Column(db.Integer, nullable=False)

    def __repr__(self):
        return ('<Group ' + self.name +'>')

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120),nullable=False)

    def __repr__(self):
        return ('<User ' +  self.username + '>')

class PasswordError(RuntimeError):
   def __init__(self, arg):
      self.args = arg

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def index():
  return redirect('login')

@app.route('/test')
def test_api_request():
  if 'credentials' not in flask.session:
    return flask.redirect('authorize')

  # Load credentials from the session.
  credentials = google.oauth2.credentials.Credentials(**flask.session['credentials'])

  drive = googleapiclient.discovery.build(API_SERVICE_NAME, API_VERSION, credentials=credentials)
  return render_template('main.html', message="Succesfully connected")

def format(result, username):
    i = 0
    out = " "
    out = '<table class="w3-table w3-striped" style="width:100"> <tr>\n '
    for file in result:
        i = i+1
        if i==3:
            out += "<td>" + "<a href= /getfile/" + file['id'] + "/" +username + "> " + file['name'] + " </a> </td> </tr> \n<tr>"
            i=0
        else:
            out += "<td>" + "<a href= /getfile/" + file['id'] + "/"+ username + "> " + file['name'] +  " </a>  </td>\n"
    if not i==0:
        print("Adding end of row at end")
        out += "</tr>"
    out += "</table>"
    return out

@app.route('/getfile/<id>/<username>')
def get_file(id, username):
    if 'credentials' not in flask.session:
      return flask.redirect('authorize')

     # Load credentials from the session.
    credentials = google.oauth2.credentials.Credentials(**flask.session['credentials'])
    drive = googleapiclient.discovery.build(API_SERVICE_NAME, API_VERSION, credentials=credentials)
    try:
        file = drive.files().get(fileId=id).execute()
        name = file['name']
        type = file['mimeType']
        request = drive.files().get_media(fileId=id)
        path = os.path.join(app.config['DOWNLOAD_FOLDER'], name)
        f = open(path, 'wb+')
        downloader = MediaIoBaseDownload(f, request)
        done = False
        while done is False:
            status, done = downloader.next_chunk()
        print("Downloaded file... decrypting")
        user_id = User.query.filter_by(username=username).first().id
        group_entries = GroupEntry.query.filter_by(user_id=user_id).all()
        outfile=False
        for entry in group_entries:
            print("group_id:",entry.group_id)
            group_id = Group.query.filter_by(id=entry.group_id).first().id
            key=entry.key
            outfile = decrypt(key, path, name, group_id)
            if not outfile == False:
                break
        message = ""
        color = ""
        print(outfile)
        if outfile==False:
            message="The file could not be decrypted as you do not have access to the group that encrypted it."
            color = "red"
        else:
            message = "The file has been decrypted and is located in your downloads folder."
            color = "green"
        return render_template('main.html', username=username, message=message, color=color)

    except Exception as error:
        print('An error occurred: ',error)
        return render_template('main.html', username=username, message="Error decrypting file", color="red")

@app.route('/authorize')
def authorize():
  # Create flow instance to manage the OAuth 2.0 Authorization Grant Flow steps.
  flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(CLIENT_SECRETS_FILE, scopes=SCOPES)

  flow.redirect_uri = flask.url_for('oauth2callback', _external=True)

  authorization_url, state = flow.authorization_url(access_type='offline',include_granted_scopes='false')
      # Enable offline access so that you can refresh an access token without
      # re-prompting the user for permission. Recommended for web server apps.

      # Enable incremental authorization. Recommended as a best practice.

  # Store the state so the callback can verify the auth server response.
  flask.session['state'] = state
  return flask.redirect(authorization_url)

@app.route('/oauth2callback')
def oauth2callback():
  # Specify the state when creating the flow in the callback so that it can
  # verified in the authorization server response.
  state = flask.session['state']

  flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(CLIENT_SECRETS_FILE, scopes=SCOPES, state=state)
  flow.redirect_uri = flask.url_for('oauth2callback', _external=True)

  # Use the authorization server's response to fetch the OAuth 2.0 tokens.
  authorization_response = flask.request.url
  flow.fetch_token(authorization_response=authorization_response)

  # Store credentials in the session.
  # ACTION ITEM: In a production app, you likely want to save these
  #              credentials in a persistent database instead.
  credentials = flow.credentials
  flask.session['credentials'] = credentials_to_dict(credentials)

  return render_template('main.html', message="Authorized. Please log-in to Secure Cloud again.", color="green")

@app.route('/revoke')
def revoke():
  if 'credentials' not in flask.session:
    return ('You need to <a href="/authorize">authorize</a> before ' + 'testing the code to revoke credentials.')

  credentials = google.oauth2.credentials.Credentials(
    **flask.session['credentials'])

  revoke = requests.post('https://accounts.google.com/o/oauth2/revoke', params={'token': credentials.token}, headers = {'content-type': 'application/x-www-form-urlencoded'})

  status_code = getattr(revoke, 'status_code')
  if status_code == 200:
    return render_template('main.html', message="Credentials revoked successfully", color="green")
  else:
    return render_template('main.html', message="Error revoking credentials", color="red")

@app.route('/files/<username>')
def show_files(username):
    if 'credentials' not in flask.session:
      return flask.redirect('authorize')

    # Load credentials from the session.
    credentials = google.oauth2.credentials.Credentials(**flask.session['credentials'])

    drive = googleapiclient.discovery.build(API_SERVICE_NAME, API_VERSION, credentials=credentials)

    result = []
    page_token = None
    counter = 0
    while True:
        try:
            param = {}
            if page_token:
                param['pageToken'] = page_token
                counter = counter+1
                if counter == 3:
                    break
            files2 = drive.files().list(**param).execute()
            result.extend(files2['files'])
            page_token = files2.get('nextPageToken')
            if not page_token:
                break
        except Exception as e:
          print('An error occurred: ',e)
          break
    result_string = format(result,username)
    path = os.path.join(app.config['TEMPLATES'], 'files.html')
    out = open(path, 'w+')
    out.write('<head>\n <meta charset="utf-8"> \n<title>Files</title>\n')
    out.write('<link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.1.3/css/bootstrap.min.css" integrity="sha384-MCw98/SFnGE8fJT3GXwEOngsV7Zt27NXFoaoApmYm81iuXoPkFOJwJ8ERdknLPMO" crossorigin="anonymous">\n')
    out.write('<link rel="stylesheet" href="https://www.w3schools.com/w3css/4/w3.css">\n')
    out.write('</head>\n <body>\n <div class="container"> \n<div class="row">\n <h1> My Files </h1> </div> <div class="row">  <div class="col-sm-6"> <p><a href="/main/')
    out.write(username)
    out.write('">Back to Main Menu</a></p> <p>\nFiles beginning with "encrypted_" have been uploaded by the CryptoApp and need to be downloaded to be decrypted. </p></div></div>\n<div class="row"> \n<div class="col-sm-1"></div> <div class="col-sm-9"> ')
    out.write(result_string)
    out.write('\n</div>\n</div>\n</div>\n \n </body>')
    out.close()
    return render_template('files.html')

@app.route('/clear')
def clear_credentials():
  if 'credentials' in flask.session:
    del flask.session['credentials']
  return render_template('main.html', message="Credentials cleared successfully", color="green")

@app.route('/upload/<username>', methods=['POST','GET'])
def upload_file(username):
    if request.method == 'POST':
        print("Post and valid")
        if 'file' not in request.files:
            return redirect('upload/'+username)
        file = request.files['file']
        if file.filename == '':
            print('No selected file')
            return redirect('upload/'+username)
        if file and allowed_file(file.filename):
            form = request.form.to_dict()
            extension = file.filename.rsplit('.', 1)[1].lower()
            filename = form['name'] + "." + extension
            filename = secure_filename(filename)
            filename = filename.replace(' ', '_')
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            group_chosen =  form['group']
            group = Group.query.filter_by(name=group_chosen).first().id
            key = GroupEntry.query.filter_by(group_id=group).first().key
            output = encrypt(filename, key, group)
            file_metadata = {'name': "encrypted_"+filename}
            credentials = google.oauth2.credentials.Credentials(**flask.session['credentials'])
            drive = googleapiclient.discovery.build(API_SERVICE_NAME, API_VERSION, credentials=credentials)
            media = MediaFileUpload(output)
            file = drive.files().create(body=file_metadata,media_body=media,fields='id').execute()
            print('File ID: ' + file.get('id'))
            return render_template('main.html', username=username)
    else:
        user_id = User.query.filter_by(username=username).first().id
        group_entries = GroupEntry.query.filter_by(user_id=user_id).all()
        groups = []
        for entry in group_entries:
            group = Group.query.filter_by(id=entry.group_id).first()
            groups.append(group)
        return render_template('form.html', message="", groups=groups, username=username)

@app.route('/login', methods=['POST', 'GET'])
def login():
    if request.method == 'POST':
        form = request.form.to_dict()
        username = form['username']
        password = form['password']
        print(username)
        try:
            res = User.query.filter_by(username=username).first()
            print(res)
            if not password == res.password:
                print("Incorrect password, try again")
                return redirect('login')
            return redirect('main/'+username)
        except Exception as e:
            return redirect('login')
    else:
        return render_template('login.html')

@app.route('/register',  methods=['POST', 'GET'])
def register():
    if request.method == 'POST':
        form = request.form.to_dict()
        user = User(username=form['username'], password=form['password'])
        db.session.add(user)
        db.session.commit()
        user = User.query.filter_by(username=form['username']).first()
        group = Group(name=("group_1_" + form['username']), creator=form['username'])
        db.session.add(group)
        db.session.commit()
        group = Group.query.filter_by(name=("group_1_" + form['username'])).first()
        randomint = str(random.randint(1000000000000000,9999999999999999))
        group_entry = GroupEntry(user_id=user.id, group_id=group.id, key=randomint)
        db.session.add(group_entry)
        db.session.commit()
        return render_template('main.html', message="User created", username=form['username'])
    else:
        return render_template('register.html', message="Error")

@app.route('/main/<username>')
def main(username):
    return render_template('main.html', username=username)

@app.route('/editgroups/<username>')
def editgroups(username):
    try:
        user = User.query.filter_by(username=username).first()
        return_groups = []
        groups = (GroupEntry.query.filter_by(user_id=user.id)).all()
        for group in groups:
            db_group = Group.query.filter_by(id=group.group_id).first()
            print(db_group.name)
            return_groups.append(db_group)
        return render_template('editgroups.html', groups=return_groups, username=username, index=len(return_groups))
    except Exception as e:
        print(e)
        return render_template('main.html', username=username)
@app.route('/editgroup/<group_id>/<username>')
def editgroup(group_id, username):
    try:
        names = []
        group_entries = GroupEntry.query.filter_by(group_id=group_id).all()
        for entry in group_entries:
            user = User.query.filter_by(id=entry.user_id).first()
            names.append(user.username)
        index = len(group_entries)
        return render_template('editgroup.html', username=username, entries=group_entries, names=names,index=index)
    except Exception as e:
        print(e)
        return render_template('main.html',username=username)

@app.route('/remove/<username>/<group_id>/<user_id>')
def remove(username, group_id, user_id):
    print("Deleting")
    group_entry = GroupEntry.query.filter_by(group_id=group_id, user_id=user_id).first()
    print(group_entry)
    db.session.delete(group_entry)
    db.session.commit()
    return redirect(url_for('editgroup',group_id=group_id,username=username))
@app.route('/groups/<username>', methods=['POST', 'GET'])
def viewgroups(username):
    try:
        if request.method=='GET':
            return_groups = []
            id = (User.query.filter_by(username=username).first()).id
            groups = (GroupEntry.query.filter_by(user_id=id)).all()
            for group in groups:
                db_group = Group.query.filter_by(id=group.group_id).first()
                return_groups.append(db_group.name)
            return render_template('view_groups.html', groups = return_groups, username=username)
        else:
            form = request.form.to_dict()
            group_name = form['group_name']
            user2add = form['added_user']
            user = User.query.filter_by(username=user2add).first()
            print(user)
            group_user = User.query.filter_by(username=username).first()
            group = Group.query.filter_by(name=group_name).first()
            print(group)
            key = GroupEntry.query.filter_by(user_id=group_user.id, group_id=group.id).first().key
            print(key)
            group_entry = GroupEntry(user_id=user.id, group_id=group.id, key=key)
            db.session.add(group_entry)
            db.session.commit()
            return_groups = []
            id = (User.query.filter_by(username=username).first()).id
            groups = (GroupEntry.query.filter_by(user_id=id)).all()
            for group in groups:
                db_group = Group.query.filter_by(id=group.group_id).first()
                return_groups.append(db_group.name)
            return render_template('view_groups.html', groups=return_groups,username=username)

    except Exception as e:
        print("Error: ",e)
        id = (User.query.filter_by(username=username).first()).id
        return_groups = []
        groups = (GroupEntry.query.filter_by(user_id=id)).all()
        for group in groups:
            db_group = Group.query.filter_by(id=group.group_id).first()
            return_groups.append(db_group.name)
        return render_template('view_groups.html', groups = return_groups, username=username)
@app.route('/add_group/<username>', methods=['POST','GET'])
def add_group(username):
    try:
        if request.method =='POST':
            form = request.form.to_dict()
            group_name=form['name']
            user = form['user']
            cur_user = (User.query.filter_by(username=username).first())
            added_user = (User.query.filter_by(username=user).first())
            created_group = Group(name=group_name, creator=cur_user.id)
            db.session.add(created_group)
            db.session.commit()
            print("Added group")
            new_group = Group.query.filter_by(name=group_name, creator=cur_user.id).first()
            key = str(random.randint(1000000000000000,9999999999999999))
            group_entry = GroupEntry(user_id=cur_user.id, group_id=new_group.id,key=key)
            group_entry2 = GroupEntry(user_id=added_user.id, group_id=new_group.id, key=key)
            db.session.add(group_entry)
            db.session.add(group_entry2)
            db.session.commit()
            return_groups=[]
            groups = (GroupEntry.query.filter_by(user_id=cur_user.id)).all()
            for group in groups:
                db_group = Group.query.filter_by(id=group.group_id).first()
                return_groups.append(db_group)
            return render_template('editgroups.html', groups=return_groups,username=username, index=len(return_groups))
        else:
            return_groups = []
            id = (User.query.filter_by(username=username).first()).id
            groups = (GroupEntry.query.filter_by(user_id=id)).all()
            for group in groups:
                db_group = Group.query.filter_by(id=group.group_id).first()
                return_groups.append(db_group.name)
            return render_template('new_group.html', username=username)
    except Exception as e:
        print(e)
        return render_template('new_group.html', username=username)
def credentials_to_dict(credentials):
  return {'token': credentials.token,
          'refresh_token': credentials.refresh_token,
          'token_uri': credentials.token_uri,
          'client_id': credentials.client_id,
          'client_secret': credentials.client_secret,
          'scopes': credentials.scopes}

def encrypt(filename, key, group_id):
    blocksize = 64*1024
    path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    output = os.path.join(app.config['ENCRYPTED_FOLDER'],"encrypted_"+filename)
    size = str(os.path.getsize(path)).zfill(16)
    group_id_str = str(group_id).zfill(16)
    iv = ''
    for i in range(16):
        iv +=  chr(random.randint(0,99))
    print(iv)
    encryptor = AES.new(key, AES.MODE_CBC, iv)
    infile = open(path, "rb")
    out = open(output, 'wb+')
    out.write(size.encode())
    out.write(iv.encode())
    out.write(group_id_str.encode())
    while True:
        block = infile.read(blocksize)
        if (len(block)==0):
            break
        elif len(block) % 16 !=0:
            block += (' ' * (16-(len(block) % 16))).encode()
        out.write(encryptor.encrypt(block))
    out.close()
    return output

def decrypt(key, filename, out_filename, group_id):
    try:
        blocksize = 64*1024
        out_filename = os.path.join(app.config['DOWNLOAD_FOLDER'], out_filename[len('encrypted_'):])
        print("Decrypting: ", filename, " to file: ", out_filename)
        with open(filename, "rb") as infile:
            filesize = infile.read(16).decode()
            print(filesize)
            iv = str(infile.read(16).decode())
            group_file_id = int(infile.read(16).decode())
            if not group_id==group_file_id:
                return False
            print("IV found:", iv)
            print("Size: ",filesize)
            decryptor = AES.new(key, AES.MODE_CBC, iv)
            with open(out_filename, 'wb+') as outfile:
                while True:
                    print("Reading block ...")
                    block = infile.read(blocksize)
                    if len(block) == 0:
                        break
                    outfile.write(decryptor.decrypt(block))
                outfile.truncate(int(filesize))
        return outfile
    except Exception as e:
        outfile = False
        print(e)
        return outfile

def bytes_to_int(bytes):
    result = 0
    for b in bytes:
        result = result * 256 + int(b)
    return result

if __name__ == '__main__':
  # When running locally, disable OAuthlib's HTTPs verification.
  # ACTION ITEM for developers:
  #     When running in production *do not* leave this option enabled.
  os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

  # Specify a hostname and port that are set as a valid redirect URI
  # for your API project in the Google API Console.
  app.run('localhost', 8080, debug=True)
