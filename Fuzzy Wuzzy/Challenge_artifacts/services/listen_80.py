from flask import Flask, request
from flask_httpauth import HTTPBasicAuth
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
auth = HTTPBasicAuth()

# Full flag is C1{S3arch_4nd_fUzz_Ch4ng3_def4ults_br34k_1n!}

users = {
    "admin": generate_password_hash("broncos")
}

@app.route('/')
def home():
    return """

|￣￣￣￣￣￣￣|
| Welcome to   |
|    the       |
| Challenge!   |
|＿＿＿＿＿＿＿|
(\__/) ||
(•ㅅ•) ||
/|  | づ

You will need to fuzz for specific values in order to build the flag.

The flag is in four parts, each is progressively more difficult.
"""

@app.route('/first')
def first():
    return "Good start!\n\nFlag part 1: C1{S3arch_"


@app.route('/apple')
def blocker():
    return "Access is denied to this directory!", 403

@app.route('/apple/thermodynamics')
def apple():
    return """
    Neat!
    
                      .-.
         heehee      /aa \_
                   __\-  / )                 .-.
         .-.      (__/    /        haha    _/oo \ 
       _/ ..\       /     \               ( \v  /__
      ( \  u/__    /       \__             \/   ___)
       \    \__)   \_.-._._   )  .-.       /     \ 
       /     \             `-`  / ee\_    /       \_
    __/       \               __\  o/ )   \_.-.__   )
   (   _._.-._/     hoho     (___   \/           '-'
    '-'                        /     \ 
                             _/       \    teehee
                            (   __.-._/

    Flag part 2: 4nd_fUzz"""

@app.route('/puppies')
def bioethics():
    user_agent = request.headers.get('User-Agent', '')
    if 'fuzz faster u fool' in user_agent.lower() or 'curl' in user_agent.lower():
        return f"Hacking Tool {user_agent} detected!", 403
    return """
            ''',
        o_)O \)____)"
        \_        )
    woof!  '',,,,,,
            ||  ||
            "--'"--'
        Filter bypassed!
    
    Flag part 3: _Ch4ng3_def4ults
    """

@auth.verify_password
def verify_password(username, password):
    if username in users and \
            check_password_hash(users.get(username), password):
        return username

@app.route('/protected')
@auth.login_required
def protected():
    # Fuzz with wfuzz -c -w ./seclists/Usernames/top-usernames-shortlist.txt -w ./seclists/Passwords/500-worst-passwords.txt -p localhost:80:HTTP --basic FUZZ:FUZ2Z --hc 401 "http://localhost/protected"
    return f"""
    / \ 
    | |
    |.|
    |.|
    |:|      __
  ,_|:|_,   /  )
    (Oo    / _I_
    +\ \   || __|
        \ \||___|
          \ /.:.\-\ 
            |.:. /-----\ 
            |___|::oOo::|
            /   |:<_T_>:|
            |_____\ ::: /
            | |  \ \:/
            | |   | |
            \ /   | \___
            / |   \_____\ 
            `-'
    This page is protected by basic HTTP auth. Welcome, {auth.current_user()}!
    """ + "Flag part 4: _br34k_1n!}"

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80, debug=True)
