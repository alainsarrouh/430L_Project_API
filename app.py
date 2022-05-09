from urllib import request
from .db_config import DB_CONFIG
from flask import Flask, request, jsonify, abort
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.sql import func
from flask_cors import CORS
from flask_marshmallow import Marshmallow
from flask_bcrypt import Bcrypt
import jwt
import datetime



app = Flask(__name__)
app.config[
    'SQLALCHEMY_DATABASE_URI'] = DB_CONFIG
CORS(app)
db = SQLAlchemy(app)
ma = Marshmallow(app)
bcrypt = Bcrypt(app)

from .model.user import User, user_schema, users_schema
from .model.transaction import Transaction, transaction_schema,transactions_schema
from .model.request import Request, request_schema,requests_schema
SECRET_KEY = "b'|\xe7\xbfU3`\xc4\xec\xa7\xa9zf:}\xb5\xc7\xb9\x139^3@Dv'"
#Adds a transaction to the database
#Needs:
#   Authorization (optional)
#   usd_amount
#   lbp_amount
#   usd_to_lbp
@app.route('/transaction', methods=['POST'])
def x():
    token = extract_auth_token(request)
    if token != None:
        try:
            user_id = decode_token(token)
        except:
            abort(403)
    else:
        user_id = None
    data = request.get_json(force=True)
    trsction = Transaction(
        usd_amount = float(data["usd_amount"]), 
        lbp_amount = float(data["lbp_amount"]), 
        usd_to_lbp = int(data["usd_to_lbp"]),
        user_id = user_id
    )
    db.session.add(trsction)
    db.session.commit()
    return jsonify(transaction_schema.dump(trsction))

#Fetches all the transactions made by a user
#Needs:
#   Authorization
@app.route('/transaction', methods=['GET'])
def getUserTransactions():
    token = extract_auth_token(request)
    if token != None:
        try:
            user_id = decode_token(token)
        except:
            abort(403)
    else:
        abort(403)
    transactions = Transaction.query.filter_by(user_id=user_id).all()
    return jsonify(transactions_schema.dump(transactions))

#Fetches the current exchange rates
#Needs no data
@app.route('/exchangeRate', methods=['GET'])
def rate():
    endDate = datetime.datetime.now()
    startDate = datetime.datetime.now() - datetime.timedelta(days=3)
    usd_to_lbp_transactions = Transaction.query.filter(Transaction.added_date.between(startDate, endDate),Transaction.usd_to_lbp == 1).all()
    lbp_to_usd_transactions = Transaction.query.filter(Transaction.added_date.between(startDate, endDate),Transaction.usd_to_lbp == 0).all()

    usd_to_lbp_avg = 0
    for t in usd_to_lbp_transactions:
        ratio = t.lbp_amount / t.usd_amount
        usd_to_lbp_avg += ratio
    if (len(usd_to_lbp_transactions) != 0):
        usd_to_lbp_avg = usd_to_lbp_avg/len(usd_to_lbp_transactions)

    lbp_to_usd_avg = 0
    for t in lbp_to_usd_transactions:
        ration = t.lbp_amount / t.usd_amount
        lbp_to_usd_avg += ration
    if (len(lbp_to_usd_transactions) != 0):
        lbp_to_usd_avg = lbp_to_usd_avg/len(lbp_to_usd_transactions)

    return jsonify({
        "usd_to_lbp": usd_to_lbp_avg,
        "lbp_to_usd": lbp_to_usd_avg
    })

#Fetches the average of each each whether it is lbp to usd or usd to lbp
#Needs no data
@app.route('/transactions', methods=['GET'])
def getTransactionsByDate():
    usdToLbpTransactions = Transaction.query.filter_by(usd_to_lbp=1).all()
    lbpToUsdTransactions = Transaction.query.filter_by(usd_to_lbp=0).all()
    days1 = [datetime.datetime.strptime(str(transaction.added_date.year)+"-"+str(transaction.added_date.month)+"-"+str(transaction.added_date.day),"%Y-%m-%d") for transaction in usdToLbpTransactions]
    days2 = [datetime.datetime.strptime(str(transaction.added_date.year)+"-"+str(transaction.added_date.month)+"-"+str(transaction.added_date.day),"%Y-%m-%d") for transaction in lbpToUsdTransactions]
    days = set(sorted(days1+days2))

    avg_by_date = []
    for day in days:
        avg_for_this_date = 0
        number_of_transactions_for_this_date = 0
        for transaction in usdToLbpTransactions:
            if (transaction.added_date>day and transaction.added_date<day+datetime.timedelta(days=1)):
                avg_for_this_date += transaction.lbp_amount/transaction.usd_amount
                number_of_transactions_for_this_date += 1
        if number_of_transactions_for_this_date != 0:
            avg_by_date.append(avg_for_this_date/number_of_transactions_for_this_date)
        else:
            avg_by_date.append(0)
    usdToLbpAverageByDate = avg_by_date

    avg_by_date = []
    for day in days:
        avg_for_this_date = 0
        number_of_transactions_for_this_date = 0
        for transaction in lbpToUsdTransactions:
            if (transaction.added_date>day and transaction.added_date<day+datetime.timedelta(days=1)):
                avg_for_this_date += transaction.lbp_amount/transaction.usd_amount
                number_of_transactions_for_this_date += 1
        if number_of_transactions_for_this_date != 0:
            avg_by_date.append(avg_for_this_date/number_of_transactions_for_this_date)
        else:
            avg_by_date.append(0)
    days = [str(day.year)+"-"+str(day.month)+"-"+str(day.day) for day in days]
    lbpToUsdAveragesByDate = avg_by_date
    
    return jsonify({
        "dates": days[::-1],
        "usdToLbpAverageByDate": usdToLbpAverageByDate[::-1],
        "lbpToUsdAveragesByDate": lbpToUsdAveragesByDate[::-1]
    })

#Adds a new user to the database
#Needs:
#   user_name
#   password
@app.route('/user', methods=['POST'])
def addUser():
    data = request.get_json(force=True)
    user = User(
        user_name = data["user_name"], 
        password = data["password"]
    )
    db.session.add(user)
    db.session.commit()
    return jsonify(user_schema.dump(user))

#gets all the users except the one that is currently logged in
#Needs:
#   Authorization
@app.route('/users', methods=['GET'])
def getAllUsers():
    token = extract_auth_token(request)
    if token != None:
        try:
            id = decode_token(token)
        except:
            abort(403)
    else:
        abort(403)
    users = User.query.all()
    users = [user for user in users if user.id != id]
    return jsonify(users_schema.dump(users))

#Authenticates a user and returns an auth token
#Needs:
#   user_name
#   password
@app.route('/authentication', methods=['POST'])
def auth():
    data = request.get_json(force=True)
    if "user_name" not in data or "password" not in data:
        abort(400)
    user = User.query.filter_by(user_name=data["user_name"]).all()
    if len(user)==0:
        abort(403)
    user = user[0]
    if not bcrypt.check_password_hash(user.hashed_password, data["password"]):
        abort(403)
    token = create_token(user.id)
    return jsonify({
        "token": token
    })

#Adds funds to the user that is currently logged in
#Needs:
#   amount_added
#   is_usd
@app.route('/wallet', methods=['PUT'])
def addFunds():
    data = request.get_json(force=True)
    token = extract_auth_token(request)
    if token != None:
        try:
            id = decode_token(token)
        except:
            abort(403)
    else:
        abort(403)
    user = User.query.filter_by(id=id).first()
    if (bool(data["is_usd"])):
        user.usd_wallet += int(data["amount_added"])
    else:
        user.lbp_wallet += int(data["amount_added"])
    db.session.commit()
    return jsonify(user_schema.dump(user))

#Fetches the wallet values of the user that is currently logged in
#Needs:
#   Authorization
@app.route('/wallet', methods=['GET'])
def getFunds():
    token = extract_auth_token(request)
    if token != None:
        try:
            id = decode_token(token)
        except:
            abort(403)
    else:
        abort(403)
    user = User.query.filter_by(id=id).first()
    return jsonify({"lbp_funds": user.lbp_wallet, "usd_funds": user.usd_wallet})

#Adds a request to the user that is currently logged in
#Needs:
#   Authorization
#   other_user_id
#   usd_amount
#   lbp_amount
#   usd_to_lbp
@app.route('/request', methods=["POST"])
def addRequest():
    data = request.get_json(force=True)
    token = extract_auth_token(request)
    if token != None:
        try:
            id = decode_token(token)
        except:
            abort(403)
    else:
        abort(403)
    user = User.query.filter_by(id=id).first()
    otherUser = User.query.filter_by(id=int(data["other_user_id"])).first()
    if (bool(data["usd_to_lbp"])):
        if (int(data["usd_amount"]) > user.usd_wallet or int(data["lbp_amount"]) > otherUser.lbp_wallet):
            abort(403)
    else:
        if (int(data["lbp_amount"]) > user.lbp_wallet or int(data["usd_amount"]) > otherUser.usd_wallet):
            abort(403)
    rqst = Request(
        usd_amount = float(data["usd_amount"]), 
        lbp_amount = float(data["lbp_amount"]), 
        usd_to_lbp = bool(data["usd_to_lbp"]),
        user_id = id,
        other_user_id = int(data["other_user_id"])
    )
    db.session.add(rqst)
    db.session.commit()
    return jsonify(request_schema.dump(rqst))

#Fetches all the requests of the user that is currently logged in
#Needs:
#   Authorization
@app.route('/request', methods=["GET"])
def getAllRequestsOfAUser():
    token = extract_auth_token(request)
    if token != None:
        try:
            id = decode_token(token)
        except:
            abort(403)
    else:
        abort(403)
    requests = Request.query.filter_by(other_user_id=id).all()
    return jsonify(requests_schema.dump(requests))

#Deletes a request 
#Needs:
#   id
@app.route('/request', methods=["DELETE"])
def deleteRequest():
    id = request.args.get('id')
    Request.query.filter_by(id=id).delete()
    db.session.commit()
    return jsonify("Success")
    
#Commits a trade and deletes the corresponding request
#Needs:
#   Authorization
#   id (of the request)
@app.route('/trade', methods=['POST'])
def trade():
    data = request.get_json(force=True)
    token = extract_auth_token(request)
    if token != None:
        try:
            id = decode_token(token)
        except:
            abort(403)
    else:
        abort(403)
    rqst = Request.query.filter_by(id=int(data["id"])).first()
    user = User.query.filter_by(id=int(rqst.user_id)).first()
    otherUser = User.query.filter_by(id=int(rqst.other_user_id)).first()
    if (bool(rqst.usd_to_lbp)):
        
        if (int(rqst.usd_amount) > user.usd_wallet or int(rqst.lbp_amount) > otherUser.lbp_wallet):
            db.session.commit()
            Request.query.filter_by(id=int(data["id"])).delete()
            abort(403)
        user.usd_wallet -= int(rqst.usd_amount)
        otherUser.usd_wallet += int(rqst.usd_amount)
        user.lbp_wallet += int(rqst.lbp_amount)
        otherUser.lbp_wallet -= int(rqst.lbp_amount)
    else:
        if (int(rqst.lbp_amount) > user.lbp_wallet or int(rqst.usd_amount) > otherUser.usd_wallet):
            db.session.commit()
            Request.query.filter_by(id=int(data["id"])).delete()
            abort(403)
        user.usd_wallet += int(rqst.usd_amount)
        otherUser.usd_wallet -= int(rqst.usd_amount)
        user.lbp_wallet -= int(rqst.lbp_amount)
        otherUser.lbp_wallet += int(rqst.lbp_amount)
    Request.query.filter_by(id=int(data["id"])).delete()
    db.session.commit()
    return jsonify("Success")

#Compares a hypotehtical transaction done at the current date vs a chosen date
#Needs chosen DateTime
#Needs value in transaction
#needs usd_to_lbp boolean
@app.route('/insight', methods=['GET'])
def compareRate():
    endDate = datetime.datetime.now()
    startDate = datetime.datetime.now() - datetime.timedelta(days=3)

    data = request.get_json(force=True)
    if (data["usd_to_lbp"]):
        usd_to_lbp_transactions = Transaction.query.filter(Transaction.added_date.between(parser.parse(data["date_to_compare"]) - datetime.timedelta(days=3),parser.parse(data["date_to_compare"])),Transaction.usd_to_lbp == 1).all()
        usd_to_lbp_avg = 0
        for t in usd_to_lbp_transactions:
            ratio = t.lbp_amount / t.usd_amount
            usd_to_lbp_avg += ratio
        if (len(usd_to_lbp_transactions) != 0):
            usd_to_lbp_avg = usd_to_lbp_avg/len(usd_to_lbp_transactions)
        else:
            abort(403)
            
            

        usd_to_lbp_transactionscurrent = Transaction.query.filter(Transaction.added_date.between(startDate,endDate),Transaction.usd_to_lbp == 1).all()
        usd_to_lbp_avg2 = 0
        for t in usd_to_lbp_transactionscurrent:
            ratio = t.lbp_amount / t.usd_amount
            print(ratio)
            usd_to_lbp_avg2 += ratio
        if (len(usd_to_lbp_transactionscurrent) != 0):
            usd_to_lbp_avg2 = usd_to_lbp_avg2/len(usd_to_lbp_transactions)
        else:
            abort(403)
        
        change = (data["value"] * usd_to_lbp_avg) -(data["value"] * usd_to_lbp_avg2)
        if (change <0):
            return jsonify({
        "loss" : True,
        "value" : -change    })

        elif (change >0):
            return jsonify({
        "loss" : False,
        "value" : change    })

    else:
            lbp_to_usd_transactions = Transaction.query.filter(Transaction.added_date.between(parser.parse(data["date_to_compare"]) - datetime.timedelta(days=3),parser.parse(data["date_to_compare"])),Transaction.usd_to_lbp == 0).all() 
            lbp_to_usd_avg = 0
            for t in lbp_to_usd_transactions:
                ratio = t.lbp_amount / t.usd_amount
                lbp_to_usd_avg += ratio
            if (len(lbp_to_usd_transactions) != 0):
                lbp_to_usd_avg = lbp_to_usd_avg/len(lbp_to_usd_transactions)
            else:
                abort(403)
           
            lbp_to_usd_transactionscurrent = Transaction.query.filter(Transaction.added_date.between(startDate,endDate),Transaction.usd_to_lbp == 0).all()
            lbp_to_usd_avg2 = 0
            for t in lbp_to_usd_transactionscurrent:
                ratio = t.lbp_amount / t.usd_amount
                lbp_to_usd_avg2 += ratio
            if (len(lbp_to_usd_transactionscurrent) != 0):
                lbp_to_usd_avg2 = lbp_to_usd_avg2/len(lbp_to_usd_transactionscurrent)
            else:
                abort(403)

            change = (data["value"]%lbp_to_usd_avg) -(data["value"]%lbp_to_usd_avg2)
            if (change <0):
                return jsonify({
            "loss" : True,
            "value" : -change    })

            elif (change >=0):
                return jsonify({
            "loss" : False,
            "value" : change    })

def create_token(user_id):
    payload = {
        'exp': datetime.datetime.utcnow() + datetime.timedelta(days=4),
        'iat': datetime.datetime.utcnow(),
        'sub': user_id
    }
    return jwt.encode(
        payload,
        SECRET_KEY,
        algorithm='HS256'
    )

def extract_auth_token(authenticated_request):
    auth_header = authenticated_request.headers.get('Authorization')
    if auth_header:
        return auth_header.split(" ")[1]
    else:
        return None

def decode_token(token):
    payload = jwt.decode(token, SECRET_KEY, 'HS256')
    return payload['sub']
