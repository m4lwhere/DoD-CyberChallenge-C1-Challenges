from flask import Flask
app = Flask(__name__)

@app.route('/')
def hello_world():
    return 'CTF{your_flag_here}'

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=51147)  # Using 51147 as an example high-numbered port
