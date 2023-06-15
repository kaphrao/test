import datetime
from flask import Flask,request,session
from flask import Flask
from flask_mysqldb import MySQL
from flask_session import Session
from datetime import timedelta
import hashlib
import jwt

app = Flask(__name__)

app.config['JSON_AS_ASCII'] = False

# configdatabase
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = 'report'

#config session
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SECRET_KEY'] = 'xxxxxxxxx'
app.config['PERMANENT_SESSION_LIFETIME'] =  timedelta(minutes=30)
app.config["SESSION_PERMANENT"] = False
Session(app)


SECRET_KEY = "XXXNSOXXX"
mysql = MySQL(app)


@app.route('/',methods = ['GET'])
def home():
    return "Hello"
    # Username = request.headers.get('Username')
    # token = request.headers.get('JWT')
    # if Username == session.get(Username) and Username !=  None:
    #     authorized,text = authorized_jwt(token,Username)
    #     if  authorized : 
    #         return {"status" : 'Success', "Username" : Username },200
    #     else :
    #         session[Username] = None
    #         session[Username + "_token"] = None 
    #         return {"status" : text},401
    # else :
    #     return {"status" : 'Invalid'},401

@app.route('/login', methods = ['POST'])
def login():
    Username = request.form['Username']
    Password = request.form['Password']
    if Username == session.get(Username) :
        return {"status" : 'Alredy login', "Username" : Username },200
    cursor  = mysql.connection.cursor()
    cursor.execute("SELECT User,Password,Salt  from user where (User = %s)", [Username])
    data = cursor.fetchall()
    cursor.close()
    if data :
        pass_get = data[0][1]
        salt = data[0][2]
        dataBase_password = hashlib.md5((pass_get + salt).encode())
         
        hash_pass = hashlib.md5(Password.encode())
        User_pass = hashlib.md5((hash_pass.hexdigest() + salt ).encode())
        
        if dataBase_password.hexdigest() == User_pass.hexdigest() :
            session[Username] = Username
            payload = {"User": Username,'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}
            encoded_jwt = jwt.encode(payload, SECRET_KEY, algorithm="HS256" )
            session[Username + "_token"] = encoded_jwt
            return  {"status" : 'Success', "token" : encoded_jwt } , 200
        else :
            return  {"status" : 'Incorrect Username or Password' } , 401
    else : 
        
        return {"status" : 'Incorrect Username or Username' } , 401 
    
def authorized_jwt(encoded_jwt,Username):
    try:  
        decoded_jwt = jwt.decode(encoded_jwt, SECRET_KEY, algorithms=['HS256'],verify=True)  
        if session.get(Username + "_token") == encoded_jwt :
            return True,decoded_jwt
        else : 
            return False,"Invalid Token"
    except jwt.exceptions.InvalidSignatureError:  
        return False, "Invalid Token Signature"
    except jwt.exceptions.ExpiredSignatureError:
        return False, "Token Expired"
        
# logout delete session
@app.route('/logout',methods = ['GET'])
def logout() :
    Username = request.headers.get('Username')
    session[Username] =  None
    session[Username + "_token"] = None
    return {"status" : 'Logout successful'} , 200

# ดาวน์โหลดรายงานรูปแบบ pdf หรือ excel 
@app.route('/report',methods = ['GET'])
def load_report() :
    pass

if __name__ == '__main__':
    app.run(debug=True)


