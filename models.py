from mongoengine import Document, StringField, DateTimeField, BooleanField, connect

# Configuration for MongoDB
# url = 'mongodb+srv://rockyranjith223:SarithaRanjith@cluster0.dfx67zc.mongodb.net/Extension_user'
url = 'mongodb+srv://rockyranjith371:VaI5mRvzH8RrWMXs@cluster0.fz5f9kn.mongodb.net/Extension_user'
try:
    connect(host=url)
    print("db connected")
except Exception as e:
    print(f"errir {e}")
# db = client['user_database']

# Model for User
class User(Document):
    email = StringField(required=True, unique=True)
    password = StringField(required=True)
    verification = BooleanField(default=False)
    otp = StringField()
    otp_expiry = DateTimeField()

    # New fields for subscription information
    subscription_status = StringField(default="inactive")  # active, inactive, cancelled
    subscription_id = StringField()
    subscription_start = DateTimeField()
    subscription_end = DateTimeField()

    
