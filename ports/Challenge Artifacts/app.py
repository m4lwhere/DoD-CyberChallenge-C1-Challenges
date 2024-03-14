from flask import Flask
app = Flask(__name__)

@app.route('/')
def hello_world():
    return 'C1{ch3ck_4ll_p0rts!}'

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=51147)  # Using 51147 as an example high-numbered port
