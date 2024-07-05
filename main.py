from datetime import datetime, timedelta
import redis
from flask import (
    Flask,
    abort,
    render_template,
    redirect,
    url_for,
    flash,
    request,
    jsonify,
)
from flask_bootstrap import Bootstrap5
from flask_ckeditor import CKEditor
from flask_gravatar import Gravatar
from flask_login import (
    UserMixin,
    login_user,
    LoginManager,
    current_user,
    logout_user,
    login_required,
)
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship, DeclarativeBase, Mapped, mapped_column
from sqlalchemy import Integer, String, Text, ForeignKey
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import (
    create_access_token,
    get_jwt_identity,
    jwt_required,
    JWTManager,
    get_jwt,
    verify_jwt_in_request,
)
from blacklist import BLACKLIST

ACCESS_EXPIRES = timedelta(hours=1)

app = Flask(__name__)
app.config["SECRET_KEY"] = "8BYkEfBA6O6donzWlSihBXox7C0sKR6b"
app.config["JWT_SECRET_KEY"] = "EzoJBiSSPiA8UhSxbSiDVp72lYSzxrAb"
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = ACCESS_EXPIRES
app.config["JWT_BLACKLIST_ENABLED"] = True
app.config["JWT_BLACKLIST_TOKEN_CHECKS"] = ["access"]
jwt = JWTManager(app)


@jwt.token_in_blocklist_loader
def check_if_token_in_blacklist(jwt_header, decrypted_token):
    return decrypted_token["jti"] in BLACKLIST


# CREATE DB
class Base(DeclarativeBase):
    pass


# Connect to Database
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///eventhub.db"
db = SQLAlchemy(model_class=Base)
db.init_app(app)


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    events = db.relationship("Event", secondary="subscribe", back_populates="users")
    messages_sent = db.relationship(
        "Message", foreign_keys="Message.sender_id", back_populates="sender"
    )
    messages_received = db.relationship(
        "Message", foreign_keys="Message.receiver_id", back_populates="receiver"
    )
    comments = db.relationship("Comment", back_populates="author")


class Event(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    background_image = db.Column(
        db.String(255)
    )  # THIS IS SUPPOSED TO HAVE A DEFAULT VALUE BRO
    category_id = db.Column(db.Integer, db.ForeignKey("category.id"), nullable=False)
    subcategory_id = db.Column(db.Integer, db.ForeignKey("sub_category.id"))
    description = db.Column(db.Text)
    event_start_date = db.Column(db.DateTime, nullable=False)
    event_end_date = db.Column(db.DateTime, nullable=False)
    location_id = db.Column(db.Integer, db.ForeignKey("address.id"), nullable=False)
    entry_fee = db.Column(db.Float, nullable=False)
    host_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    is_private = db.Column(db.Boolean, default=False, nullable=False)
    users = db.relationship("User", secondary="subscribe", back_populates="events")
    category = db.relationship("Category", back_populates="events")
    subcategory = db.relationship("SubCategory", back_populates="events")
    location = db.relationship("Address", back_populates="events")
    comments = db.relationship("Comment", back_populates="event")

    def to_dict(self):
        return {
            column.name: getattr(self, column.name) for column in self.__table__.columns
        }


class Category(db.Model):  # THIS SHOULD HAVE A ICON_URL ATTRIBUTE
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    events = db.relationship("Event", back_populates="category")


class SubCategory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    category_id = db.Column(db.Integer, db.ForeignKey("category.id"))
    events = db.relationship("Event", back_populates="subcategory")


class Subscribe(db.Model):
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), primary_key=True)
    event_id = db.Column(db.Integer, db.ForeignKey("event.id"), primary_key=True)
    is_confirmed = db.Column(db.Boolean, default=False)
    is_favorited = db.Column(db.Boolean, default=False)


class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    content = db.Column(db.Text, nullable=False)
    date = db.Column(db.DateTime, default=datetime.now())
    sender = db.relationship(
        "User", foreign_keys=[sender_id], back_populates="messages_sent"
    )
    receiver = db.relationship(
        "User", foreign_keys=[receiver_id], back_populates="messages_received"
    )


class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    event_id = db.Column(db.Integer, db.ForeignKey("event.id"), nullable=False)
    content = db.Column(db.Text, nullable=False)
    author = db.relationship("User", back_populates="comments")
    event = db.relationship("Event", back_populates="comments")


class Address(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    country = db.Column(db.String(100), nullable=False)
    state = db.Column(db.String(100), nullable=False)
    city = db.Column(db.String(100), nullable=False)
    zip_code = db.Column(db.String(20), nullable=False)
    complement = db.Column(db.String(255))  # THIS IS NOT SUPPOSED TO BE NULLABLE
    events = db.relationship("Event", back_populates="location")


with app.app_context():
    db.create_all()


def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        verify_jwt_in_request()
        current_user_id = get_jwt_identity()
        user = db.session.execute(
            db.select(User).where(User.id == current_user_id)
        ).scalar()

        if user.id != 1:
            return jsonify({"message": "Only Admin users can perform this action"}), 403
        return f(*args, **kwargs)

    return decorated_function


def parse_date(form_field):
    date_format = "%Y-%m-%dT%H:%M:%S"
    date_string = request.form[form_field]
    return datetime.strptime(date_string, date_format)


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/register", methods=["POST"])
def create_user():
    result = db.session.execute(
        db.select(User).where(User.email == request.form["email"])
    )
    user = result.scalar()
    if user:
        return jsonify({"message": "A user with that email already exists!"}), 400
    else:
        hash_and_salted_password = generate_password_hash(
            request.form["password"], method="pbkdf2:sha256", salt_length=8
        )
        new_user = User(
            email=request.form["email"],
            password=hash_and_salted_password,
            name=request.form["name"],
        )
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return jsonify({"message": "User created successfully!"}), 201


@app.route("/login", methods=["POST"])
def login():
    email = request.form["email"]
    result = db.session.execute(db.select(User).where(User.email == email))
    user = result.scalar()
    if not user:
        return jsonify({"message": "A user with that email doesn't exist!"}), 401
    elif not check_password_hash(user.password, request.form["password"]):
        return jsonify({"message": "Password incorrect. Please try again."}), 401
    else:
        access_token = create_access_token(identity=user.id)
        return jsonify(access_token=access_token)


@app.route("/logout", methods=["POST"])
@jwt_required()
def logout():
    jti = get_jwt()["jti"]
    BLACKLIST.add(jti)
    return jsonify(msg="Successfully logged out"), 200


@app.route("/new-category", methods=["POST"])
@jwt_required()
@admin_only
def create_category():
    result = db.session.execute(
        db.select(Category).where(Category.name == request.form["name"])
    )
    category = result.scalar()
    if category:
        return jsonify({"message": "A category with that name already exists!"}), 400
    else:
        new_category = Category(name=request.form["name"])
        db.session.add(new_category)
        db.session.commit()
        return jsonify({"message": "Category created successfully!"}), 201


@app.route("/new-address", methods=["POST"])
@jwt_required()
@admin_only
def add_address():
    new_address = Address(
        country=request.form["country"],
        state=request.form["state"],
        city=request.form["city"],
        zip_code=request.form["zip-code"],
        complement=request.form["complement"],
    )
    db.session.add(new_address)
    db.session.commit()
    return jsonify({"message": "Address created successfully!"}), 201


@app.route("/new-event", methods=["POST"])
@jwt_required()
def create_event():
    result = db.session.execute(
        db.select(Category).where(Category.name == request.form["category"])
    )
    category = result.scalar()

    result2 = db.session.execute(
        db.select(Address).where(
            Address.complement == request.form["location"]
        )  # THIS DOESNT REALLY MATTER, WE'LL BE USING AN API FOR THIS LATER.
    )
    address = result2.scalar()

    parsed_start_date = parse_date("start-date")
    parsed_end_date = parse_date("end-date")

    new_event = Event(
        title=request.form["title"],
        category_id=category.id,
        description=request.form["description"],
        event_start_date=parsed_start_date,
        event_end_date=parsed_end_date,
        location_id=address.id,
        entry_fee=request.form["entry-fee"],
        host_id=current_user.id,
    )
    db.session.add(new_event)
    db.session.commit()
    return jsonify({"message": "Event created successfully!"}), 201


@app.route("/feed")  # This currently gets all events, not a subset of events
@jwt_required()
def get_all_events():
    result = db.session.execute(db.select(Event))
    all_events = result.scalars().all()
    return jsonify(events=[event.to_dict() for event in all_events])


@app.route("/event/<int:event_id>")
@jwt_required()
def get_event_by_id(event_id):
    event = db.session.execute(db.select(Event).where(Event.id == event_id)).scalar()
    if event:
        return jsonify(event.to_dict()), 200
    else:
        return jsonify({"message": "An event with that id doesn't exist!"}), 404


@app.route("/search")
@jwt_required()
def search_event_by_title():
    search_query = request.args.get("q")
    results = (
        db.session.query(Event).filter(Event.title.ilike(f"%{search_query}%")).all()
    )
    if results:
        return jsonify(events=[event.to_dict() for event in results])
    else:
        return (
            jsonify(
                error={"Not Found": "Sorry, no events matching that name were found."}
            ),
            404,
        )


@app.route("/event/<int:event_id>", methods=["POST"])
@jwt_required()
def update_event(event_id):
    event = db.session.execute(db.select(Event).where(Event.id == event_id)).scalar()
    if event:
        result = db.session.execute(
            db.select(Category).where(Category.name == request.form["category"])
        )
        category = result.scalar()

        result2 = db.session.execute(
            db.select(Address).where(
                Address.complement == request.form["location"]
            )  # THIS DOESNT REALLY MATTER, WE'LL BE USING AN API FOR THIS LATER.
        )
        address = result2.scalar()

        parsed_start_date = parse_date("start-date")
        parsed_end_date = parse_date("end-date")

        event.title = request.form["title"]
        event.category_id = category.id
        event.description = request.form["description"]
        event.event_start_date = parsed_start_date
        event.event_end_date = parsed_end_date
        event.location_id = address.id
        event.entry_fee = request.form["entry-fee"]
        event.host_id = current_user.id

        db.session.commit()
        return jsonify({"message": "Event updated successfully!"}), 200
    else:
        return jsonify({"message": "An event with that id doesn't exist!"}), 404


@app.route("/delete-event/<int:event_id>", methods=["DELETE"])
@jwt_required()
def delete_event(event_id):
    event_to_delete = db.get_or_404(Event, event_id)
    db.session.delete(event_to_delete)
    db.session.commit()
    return jsonify({"message": "Event deleted successfully!"}), 200


# @app.route(
#     "/delete-user/<int:user_id>"
# )  # THIS SHOULD ONLY WORK FOR THE CURRENT_USER'S ID
# def delete_user(user_id):
#     user_to_delete = db.get_or_404(User, user_id)
#     db.session.delete(user_to_delete)
#     db.session.commit()
#     return jsonify({"message": "User account deleted successfully!"}), 200


if __name__ == "__main__":
    app.run(debug=True)
