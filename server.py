'''from flask import Flask
from routes.auth import auth_routes
from flask_cors import CORS 
# from routes.user import user_routes

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "http://localhost:3000"}})

# Registering routes
app.register_blueprint(auth_routes)
# app.register_blueprint(user_routes)

if __name__ == '__main__':
    app.run(debug=True)
'''
# app.py

# from flask import Flask
# from flask_cors import CORS
# from routes.auth import auth_routes
# from routes.functions import function_routes

# app = Flask(__name__)
# CORS(app)

# # Registering routes
# app.register_blueprint(auth_routes, url_prefix='/auth')
# app.register_blueprint(function_routes, url_prefix='/functions')

# if __name__ == '__main__':
#     app.run(debug=True)


from flask import Flask
from routes.auth import auth_routes
from routes.functions import function_routes
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

# Registering routes
app.register_blueprint(auth_routes)
app.register_blueprint(function_routes)

if __name__ == '__main__':
    app.run(debug=True)
