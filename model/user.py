from ..app import db, ma, bcrypt

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_name = db.Column(db.String(30), unique=True)
    hashed_password = db.Column(db.String(128))
    lbp_wallet = db.Column(db.Integer)
    usd_wallet = db.Column(db.Integer)

    def __init__(self, user_name, password):
        super(User, self).__init__(user_name=user_name)
        self.hashed_password = bcrypt.generate_password_hash(password)
        self.lbp_wallet = 0
        self.usd_wallet = 0

class UserSchema(ma.Schema):
    class Meta:
        fields = ("id", "user_name", "lbp_wallet","usd_wallet")
        model = User

user_schema = UserSchema()
users_schema = UserSchema(many=True)