from flask import Flask

app = Flask(__name__)

app.config['JSON_AS_ASCII'] = False


@app.route('/',methods = ['GET'])
def home():
    return "Hello"


if __name__ == '__main__':
    app.run(debug=True)