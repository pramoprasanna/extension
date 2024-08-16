# # auth.py

# from flask import Blueprint, request, jsonify
# from models import User
# from utils import send_otp, generate_otp
# import bcrypt
# import datetime

# auth_routes = Blueprint('auth', __name__)

# @auth_routes.route('/register', methods=['POST'])
# def register(): 
#     data = request.json
#     email = data.get('email')
#     password = data.get('password')

#     # Check if user already exists
#     if User.objects(email=email):
#         return jsonify({'message': 'User already exists'}), 400

#     # Generate OTP and save it in the database with an expiry time
#     otp = generate_otp()
#     otp_expiry = datetime.datetime.now() + datetime.timedelta(minutes=5)
#     user = User(email=email, password=bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()), otp=otp, otp_expiry=otp_expiry)
#     user.save()

#     # Send OTP to the user's email
#     send_otp(email, otp)

#     return jsonify({'message': 'OTP sent successfully'}), 200

# @auth_routes.route('/verify_otp', methods=['POST'])
# def verify_otp():
#     data = request.json
#     email = data.get('email')
#     otp_entered = data.get('otp')

#     # Find user by email and OTP
#     user = User.objects(email=email, otp=otp_entered).first()
#     if not user:
#         return jsonify({'message': 'Invalid OTP'}), 400

#     # Check if OTP is expired
#     if datetime.datetime.now() > user.otp_expiry:
#         return jsonify({'message': 'OTP has expired'}), 400

#     # Set verification status to True
#     user.verification = True
#     user.save()

#     return jsonify({'message': 'OTP verified successfully'}), 200

# # resent the otp / generate the new otp
# @auth_routes.route('/resend_otp', methods=['POST'])
# def resend_otp():
#     data = request.json
#     email = data.get('email')

#     # Find the user by email
#     user = User.objects(email=email).first()
#     if not user:
#         return jsonify({'message': 'User not found'}), 404

#     # Generate a new OTP
#     otp = generate_otp()
#     otp_expiry = datetime.datetime.now() + datetime.timedelta(minutes=5)

#     # Update the user's OTP and OTP expiry in the database
#     user.otp = otp
#     user.otp_expiry = otp_expiry
#     user.save()

#     # Send the new OTP to the user's email
#     send_otp(email, otp)

#     return jsonify({'message': 'New OTP sent successfully'}), 200

# @auth_routes.route('/login', methods=['POST'])
# def login():
#     data = request.json
#     email = data.get('email')
#     password = data.get('password')

#     # Find user by email
#     user = User.objects(email=email).first()
#     if not user:
#         return jsonify({'message': 'User does not exist'}), 404

#     # Check if user is verified
#     if not user.verification:
#         return jsonify({'message': 'User not verified'}), 400

#     # Check if password is correct
#     if not bcrypt.checkpw(password.encode('utf-8'), user.password.encode('utf-8')):
#         return jsonify({'message': 'Incorrect password'}), 400

#     return jsonify({'message': 'Login successful'}), 200



# ''' 
#     # above the codes no bugs
#     # below the cmd may need bug fix
# '''

# @auth_routes.route('/forgot_password', methods=['POST'])
# def forgot_password():
#     data = request.json
#     email = data.get('email')

#     # Find user by email
#     user = User.objects(email=email).first()
#     if not user:
#         return jsonify({'message': 'User not found'}), 404

#     # Generate a new OTP
#     otp = generate_otp()
#     otp_expiry = datetime.datetime.now() + datetime.timedelta(minutes=5)

#     # Update the user's OTP and OTP expiry in the database
#     user.otp = otp
#     user.otp_expiry = otp_expiry
#     user.save()

#     # Send the OTP to the user's email
#     send_otp(email, otp)

#     return jsonify({'message': 'OTP sent successfully'}), 200


# # @auth_routes.route('/reset_password', methods=['POST'])
# # def reset_password():
# #     data = request.json
# #     email = data.get('email')
# #     new_password = data.get('new_password')
# #     print(email,new_password)
# #     # Find user by email
# #     user = User.objects(email=email).first()
# #     print(user.password,new_password)
# #     if not user:
# #         return jsonify({'message': 'User not found'}), 404

# #     try:
# #         # Update the user's password
# #         user.password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
# #         print(user.email, user.password)
# #         user.save()
# #     except Exception as e:
# #         return jsonify({'message': 'Failed to reset password. Please try again.'}), 500

# #     return jsonify({'message': 'Password reset successfully'}), 200

# @auth_routes.route('/reset_password', methods=['POST'])
# def reset_password():
#     data = request.json
#     email = data.get('email')
#     new_password = data.get('new_password')

#     # Debugging: Print incoming data
#     print(f"Email: {email}, New Password: {new_password}")

#     # Check if email and new_password are provided
#     if not email or not new_password:
#         return jsonify({'message': 'Email and new password are required'}), 400

#     # Find user by email
#     user = User.objects(email=email).first()
#     if not user:
#         return jsonify({'message': 'User not found'}), 404

#     try:
#         # Update the user's password
#         hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
#         user.password = hashed_password
#         user.save()
        
#         # Debugging: Print success
#         print(f"Password for user {user.email} reset successfully")
#     except Exception as e:
#         print(f"Error resetting password: {e}")
#         return jsonify({'message': 'Failed to reset password. Please try again.'}), 500

#     return jsonify({'message': 'Password reset successfully'}), 200



# from flask import Blueprint, request, jsonify
# from models import User
# from utils import send_otp, generate_otp
# import bcrypt
# import datetime
# import jwt
# import os

# auth_routes = Blueprint('auth', __name__)

# # Secret key for encoding the JWT
# SECRET_KEY = 'eyJhbGciOiJIUzI1NiJ9.eyJSb2xlIjoiQWRtaW4iLCJJc3N1ZXIiOiJJc3N1ZXIiLCJVc2VybmFtZSI6IkphdmFJblVzZSIsImV4cCI6MTcyMDc2Njk0OSwiaWF0IjoxNzIwNzY2OTQ5fQ.LnkFrSaEzFEfCo7E60s8JvowWZFyG9Egk4quv0d9-QQ'


# #  IPQS API Key
# API_KEY = 'w0REndl0EIym4aly4naTP21ATEq1p335'


# def validate_email(email):
#     url = f'https://ipqualityscore.com/api/json/email/{API_KEY}/{email}'
#     response = requests.get(url)
#     if response.status_code == 200:
#         result = response.json()
#         return result.get('valid', False)
#     return False

# @auth_routes.route('/register', methods=['POST'])
# def register():
#     data = request.json
#     email = data.get('email')
#     password = data.get('password')

#     # Validate email
#     if not validate_email(email):
#         return jsonify({'message': 'Invalid email'}), 400
    
#     # Check if user already exists
#     if User.objects(email=email):
#         return jsonify({'message': 'User already exists'}), 400

#     # Generate OTP and save it in the database with an expiry time
#     otp = generate_otp()
#     otp_expiry = datetime.datetime.now() + datetime.timedelta(minutes=5)
#     user = User(email=email, password=bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8'), otp=otp, otp_expiry=otp_expiry)
#     user.save()

#     # Send OTP to the user's email
#     send_otp(email, otp)

#     return jsonify({'message': 'OTP sent successfully'}), 200

# @auth_routes.route('/verify_otp', methods=['POST'])
# def verify_otp():
#     data = request.json
#     email = data.get('email')
#     otp_entered = data.get('otp')

#     # Find user by email and OTP
#     user = User.objects(email=email, otp=otp_entered).first()
#     if not user:
#         return jsonify({'message': 'Invalid OTP'}), 400

#     # Check if OTP is expired
#     if datetime.datetime.now() > user.otp_expiry:
#         return jsonify({'message': 'OTP has expired'}), 400

#     # Set verification status to True
#     user.verification = True
#     user.save()

#     return jsonify({'message': 'OTP verified successfully'}), 200

# @auth_routes.route('/resend_otp', methods=['POST'])
# def resend_otp():
#     data = request.json
#     email = data.get('email')

#     # Find the user by email
#     user = User.objects(email=email).first()
#     if not user:
#         return jsonify({'message': 'User not found'}), 404

#     # Generate a new OTP
#     otp = generate_otp()
#     otp_expiry = datetime.datetime.now() + datetime.timedelta(minutes=5)

#     # Update the user's OTP and OTP expiry in the database
#     user.otp = otp
#     user.otp_expiry = otp_expiry
#     user.save()

#     # Send the new OTP to the user's email
#     send_otp(email, otp)

#     return jsonify({'message': 'New OTP sent successfully'}), 200

# @auth_routes.route('/login', methods=['POST'])
# def login():
#     data = request.json
#     email = data.get('email')
#     password = data.get('password')

#     # Find user by email
#     user = User.objects(email=email).first()
#     if not user:
#         return jsonify({'message': 'User does not exist'}), 404

#     # Check if user is verified
#     if not user.verification:
#         return jsonify({'message': 'User not verified'}), 400

#     # Check if password is correct
#     if not bcrypt.checkpw(password.encode('utf-8'), user.password.encode('utf-8')):
#         return jsonify({'message': 'Incorrect password'}), 400

#     # Generate JWT token
#     token = jwt.encode({'email': email, 'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)}, SECRET_KEY, algorithm='HS256')

#     return jsonify({'message': 'Login successful', 'token': token}), 200

# @auth_routes.route('/forgot_password', methods=['POST'])
# def forgot_password():
#     data = request.json
#     email = data.get('email')

#     # Find user by email
#     user = User.objects(email=email).first()
#     if not user:
#         return jsonify({'message': 'User not found'}), 404

#     # Generate a new OTP
#     otp = generate_otp()
#     otp_expiry = datetime.datetime.now() + datetime.timedelta(minutes=5)

#     # Update the user's OTP and OTP expiry in the database
#     user.otp = otp
#     user.otp_expiry = otp_expiry
#     user.save()

#     # Send the OTP to the user's email
#     send_otp(email, otp)

#     return jsonify({'message': 'OTP sent successfully'}), 200

# @auth_routes.route('/reset_password', methods=['POST'])
# def reset_password():
#     data = request.json
#     email = data.get('email')
#     new_password = data.get('new_password')

#     # Debugging: Print incoming data
#     print(f"Email: {email}, New Password: {new_password}")

#     # Check if email and new_password are provided
#     if not email or not new_password:
#         return jsonify({'message': 'Email and new password are required'}), 400

#     # Find user by email
#     user = User.objects(email=email).first()
#     if not user:
#         return jsonify({'message': 'User not found'}), 404

#     try:
#         # Update the user's password
#         hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
#         user.password = hashed_password
#         user.save()
        
#         # Debugging: Print success
#         print(f"Password for user {user.email} reset successfully")
#     except Exception as e:
#         print(f"Error resetting password: {e}")
#         return jsonify({'message': 'Failed to reset password. Please try again.'}), 500

#     return jsonify({'message': 'Password reset successfully'}), 200

# def token_required(f):
#     def decorator(*args, **kwargs):
#         token = None
#         if 'Authorization' in request.headers:
#             token = request.headers['Authorization'].split(" ")[1]
        
#         if not token:
#             return jsonify({'message': 'Token is missing'}), 401
        
#         try:
#             data = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
#             current_user = User.objects(email=data['email']).first()
#         except Exception as e:
#             print(f"Token verification failed: {e}")
#             return jsonify({'message': 'Token is invalid'}), 401
        
#         return f(current_user, *args, **kwargs)
#     return decorator

# @auth_routes.route('/protected', methods=['GET'])
# @token_required
# def protected(current_user):
#     return jsonify({'message': 'This is a protected route', 'user': current_user.email})

# auth.py

from flask import Blueprint, request, jsonify
from models import User
from utils import send_otp, generate_otp
import bcrypt
import datetime
import jwt
import os
import requests

auth_routes = Blueprint('auth', __name__)

# Secret key for encoding the JWT
SECRET_KEY = 'eyJhbGciOiJIUzI1NiJ9.eyJSb2xlIjoiQWRtaW4iLCJJc3N1ZXIiOiJJc3N1ZXIiLCJVc2VybmFtZSI6IkphdmFJblVzZSIsImV4cCI6MTcyMDc2Njk0OSwiaWF0IjoxNzIwNzY2OTQ5fQ.LnkFrSaEzFEfCo7E60s8JvowWZFyG9Egk4quv0d9-QQ'


# IPQS API Key
API_KEY = 'w0REndl0EIym4aly4naTP21ATEq1p335'

def validate_email(email):
    url = f'https://ipqualityscore.com/api/json/email/{API_KEY}/{email}'
    response = requests.get(url)
    if response.status_code == 200:
        result = response.json()
        return result.get('valid', False)
    return False

@auth_routes.route('/register', methods=['POST'])
def register():
    data = request.json
    email = data.get('email')
    password = data.get('password')

    # Validate email
    if not validate_email(email):
        return jsonify({'message': 'Invalid email'}), 400

    # Check if user already exists
    if User.objects(email=email):
        return jsonify({'message': 'User already exists'}), 400

    # Generate OTP and save it in the database with an expiry time
    otp = generate_otp()
    otp_expiry = datetime.datetime.now() + datetime.timedelta(minutes=5)
    user = User(email=email, password=bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8'), otp=otp, otp_expiry=otp_expiry)
    user.save()

    # Send OTP to the user's email
    send_otp(email, otp)

    return jsonify({'message': 'OTP sent successfully'}), 200

@auth_routes.route('/verify_otp', methods=['POST'])
def verify_otp():
    data = request.json
    email = data.get('email')
    otp_entered = data.get('otp')

    # Find user by email and OTP
    user = User.objects(email=email, otp=otp_entered).first()
    if not user:
        return jsonify({'message': 'Invalid OTP'}), 400

    # Check if OTP is expired
    if datetime.datetime.now() > user.otp_expiry:
        return jsonify({'message': 'OTP has expired'}), 400

    # Set verification status to True
    user.verification = True
    user.save()

    return jsonify({'message': 'OTP verified successfully'}), 200

@auth_routes.route('/resend_otp', methods=['POST'])
def resend_otp():
    data = request.json
    email = data.get('email')

    # Find the user by email
    user = User.objects(email=email).first()
    if not user:
        return jsonify({'message': 'User not found'}), 404

    # Generate a new OTP
    otp = generate_otp()
    otp_expiry = datetime.datetime.now() + datetime.timedelta(minutes=5)

    # Update the user's OTP and OTP expiry in the database
    user.otp = otp
    user.otp_expiry = otp_expiry
    user.save()

    # Send the new OTP to the user's email
    send_otp(email, otp)

    return jsonify({'message': 'New OTP sent successfully'}), 200

@auth_routes.route('/login', methods=['POST'])
def login():
    data = request.json
    email = data.get('email')
    password = data.get('password')
    # Find user by email
    user = User.objects(email=email).first()
    if not user:
        return jsonify({'message': 'User does not exist'}), 404

    # Check if user is verified
    if not user.verification:
        return jsonify({'message': 'User not verified'}), 400

    # Check if password is correct
    if not bcrypt.checkpw(password.encode('utf-8'), user.password.encode('utf-8')):
        return jsonify({'message': 'Incorrect password'}), 400

    # Generate JWT token
    token = jwt.encode({'email': email, 'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)}, SECRET_KEY, algorithm='HS256')

    return jsonify({'message': 'Login successful', 'token': token}), 200

@auth_routes.route('/forgot_password', methods=['POST'])
def forgot_password():
    data = request.json
    email = data.get('email')

    # Find user by email
    user = User.objects(email=email).first()
    if not user:
        return jsonify({'message': 'User not found'}), 404

    # Generate a new OTP
    otp = generate_otp()
    otp_expiry = datetime.datetime.now() + datetime.timedelta(minutes=5)

    # Update the user's OTP and OTP expiry in the database
    user.otp = otp
    user.otp_expiry = otp_expiry
    user.save()

    # Send the OTP to the user's email
    send_otp(email, otp)

    return jsonify({'message': 'OTP sent successfully'}), 200

@auth_routes.route('/reset_password', methods=['POST'])
def reset_password():
    data = request.json
    email = data.get('email')
    new_password = data.get('new_password')

    # Debugging: Print incoming data
    print(f"Email: {email}, New Password: {new_password}")

    # Check if email and new_password are provided
    if not email or not new_password:
        return jsonify({'message': 'Email and new password are required'}), 400

    # Find user by email
    user = User.objects(email=email).first()
    if not user:
        return jsonify({'message': 'User not found'}), 404

    try:
        # Update the user's password
        hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        user.password = hashed_password
        user.save()
        
        # Debugging: Print success
        print(f"Password for user {user.email} reset successfully")
    except Exception as e:
        print(f"Error resetting password: {e}")
        return jsonify({'message': 'Failed to reset password. Please try again.'}), 500

    return jsonify({'message': 'Password reset successfully'}), 200

def token_required(f):
    def decorator(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            token = request.headers['Authorization'].split(" ")[1]
        
        if not token:
            return jsonify({'message': 'Token is missing'}), 401
        
        try:
            data = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
            current_user = User.objects(email=data['email']).first()
        except Exception as e:
            print(f"Token verification failed: {e}")
            return jsonify({'message': 'Token is invalid'}), 401
        
        return f(current_user, *args, **kwargs)
    return decorator

@auth_routes.route('/protected', methods=['GET'])
@token_required
def protected(current_user):
    return jsonify({'message': 'This is a protected route', 'user': current_user.email})
