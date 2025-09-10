from flask import Flask

app = Flask(__name__) # This is a simple and small Flask app.

@app.route('/')
def hello_world():
    return 'Hello, Docker!'

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')