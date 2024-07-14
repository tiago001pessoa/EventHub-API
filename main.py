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
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship, DeclarativeBase, Mapped, mapped_column
from sqlalchemy import Integer, String, Text, ForeignKey, func
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


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    events = db.relationship(
        "Event", secondary="event_attendance", back_populates="users"
    )
    messages_sent = db.relationship(
        "Message", foreign_keys="Message.sender_id", back_populates="sender"
    )
    read_messages = relationship("ReadMessage", back_populates="user")
    comments = db.relationship("Comment", back_populates="author")
    profile = db.relationship("Profile", uselist=False, back_populates="user")
    chats = db.relationship(
        "Chat", secondary="user_chat", back_populates="participants"
    )


class Event(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    background_image = db.Column(db.String(255))
    category_id = db.Column(db.Integer, db.ForeignKey("category.id"), nullable=False)
    description = db.Column(db.Text)
    event_start_date = db.Column(db.DateTime, nullable=False)
    event_end_date = db.Column(db.DateTime, nullable=False)
    location_id = db.Column(db.Integer, db.ForeignKey("address.id"), nullable=False)
    entry_fee = db.Column(db.Float, nullable=False)
    host_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    is_private = db.Column(db.Boolean, default=False, nullable=False)
    users = db.relationship(
        "User", secondary="event_attendance", back_populates="events"
    )
    category = db.relationship("Category", back_populates="events")
    location = db.relationship("Address", back_populates="events")
    comments = db.relationship("Comment", back_populates="event")

    def to_dict(self):
        return {
            column.name: getattr(self, column.name) for column in self.__table__.columns
        }


class Category(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    subcategory = db.Column(db.String(100), nullable=True)
    events = db.relationship("Event", back_populates="category")


class EventAttendance(db.Model):
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), primary_key=True)
    event_id = db.Column(db.Integer, db.ForeignKey("event.id"), primary_key=True)
    is_confirmed = db.Column(db.Boolean, default=False)
    is_favorited = db.Column(db.Boolean, default=False)


class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    chat_id = db.Column(db.Integer, db.ForeignKey("chat.id"), nullable=False)
    content = db.Column(db.Text, nullable=False)
    sent_at = db.Column(db.DateTime, default=datetime.now())
    sender = db.relationship(
        "User", foreign_keys=[sender_id], back_populates="messages_sent"
    )
    chat = db.relationship("Chat", back_populates="messages")
    read_by_users = db.relationship("ReadMessage", back_populates="message")


class Comment(db.Model):
    __tablename__ = "comment"
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    event_id = db.Column(db.Integer, db.ForeignKey("event.id"), nullable=False)
    parent_id = db.Column(db.Integer, db.ForeignKey("comment.id"), nullable=True)
    content = db.Column(db.Text, nullable=False)
    replies = db.relationship("Comment", back_populates="parent", remote_side=[id])
    author = db.relationship("User", back_populates="comments")
    event = db.relationship("Event", back_populates="comments")
    replies = db.relationship("Comment", back_populates="parent", remote_side=[id])
    parent = db.relationship(
        "Comment", back_populates="replies", remote_side=[parent_id]
    )


class Address(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    country = db.Column(db.String(100), nullable=False)
    state = db.Column(db.String(100), nullable=False)
    city = db.Column(db.String(100), nullable=False)
    zip_code = db.Column(db.String(20), nullable=False)
    complement = db.Column(db.String(255), nullable=False)
    events = db.relationship("Event", back_populates="location")
    residents = db.relationship("Profile", back_populates="address")


class Profile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    pic = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=datetime.now())
    date_of_birth = db.Column(db.Date)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    address_id = db.Column(db.Integer, db.ForeignKey("address.id"), nullable=False)
    user = db.relationship("User", back_populates="profile")
    address = db.relationship("Address", back_populates="residents")


class Chat(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    participants = db.relationship(
        "User", secondary="user_chat", back_populates="chats"
    )
    messages = db.relationship("Message", back_populates="chat")


class UserChat(db.Model):
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), primary_key=True)
    chat_id = db.Column(db.Integer, db.ForeignKey("chat.id"), primary_key=True)


class ReadMessage(db.Model):
    message_id = db.Column(db.Integer, db.ForeignKey("message.id"), primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), primary_key=True)
    read_at = db.Column(db.DateTime, default=datetime.now())
    message = db.relationship("Message", back_populates="read_by_users")
    user = db.relationship("User", back_populates="read_messages")


with app.app_context():
    # db.drop_all()
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
    data = request.get_json()
    date_string = data.get(form_field)
    return datetime.strptime(date_string, date_format)


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/feed")  # This currently gets all events, not a subset of events
@jwt_required()
def get_all_events():
    result = db.session.execute(db.select(Event))
    all_events = result.scalars().all()
    return jsonify(events=[event.to_dict() for event in all_events])


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
        access_token = create_access_token(identity=new_user.id)
        return (
            jsonify(
                {"message": "User created successfully!", "access_token": access_token}
            ),
            201,
        )


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


@app.route("/category", methods=["POST"])
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


@app.route("/address", methods=["POST"])
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


@app.route("/event", methods=["POST"])
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

    current_user_id = get_jwt_identity()

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
        host_id=current_user_id,
    )
    db.session.add(new_event)
    db.session.commit()
    return jsonify({"message": "Event created successfully!"}), 201


@app.route("/event/<int:event_id>", methods=["GET", "PUT"])
@jwt_required()
def get_event_by_id(event_id):
    if request.method == "PUT":
        user_id = get_jwt_identity()
        data = request.get_json()
        is_confirmed = data.get("is_confirmed", False)
        is_favorited = data.get("is_favorited", False)

        if is_confirmed and is_favorited:
            return (
                jsonify(
                    {
                        "message": "Cannot confirm and favorite an event at the same time."
                    }
                ),
                400,
            )

        event_attendance = EventAttendance.query.filter_by(
            user_id=user_id, event_id=event_id
        ).first()

        if event_attendance:
            event_attendance.is_confirmed = is_confirmed
            event_attendance.is_favorited = is_favorited
            if not is_confirmed and not is_favorited:
                db.session.delete(event_attendance)
        else:
            if is_confirmed or is_favorited:
                event_attendance = EventAttendance(
                    user_id=user_id,
                    event_id=event_id,
                    is_confirmed=is_confirmed,
                    is_favorited=is_favorited,
                )
                db.session.add(event_attendance)

        db.session.commit()
        return jsonify({"message": "Event attendance updated successfully"}), 200
    else:
        event = db.session.execute(
            db.select(Event).where(Event.id == event_id)
        ).scalar()

        event_attendences = db.session.execute(
            db.select(func.count(EventAttendance.event_id)).where(
                EventAttendance.event_id == event_id
            )
        ).scalar()

        event_details_dict = event.to_dict()

        participants = {"responses": event_attendences}

        event_details_dict.update(participants)

        if event:
            return jsonify(event_details_dict), 200
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


@app.route("/event/<int:event_id>", methods=["PUT"])
@jwt_required()
def update_event(event_id):
    data = request.get_json()
    event = db.session.execute(db.select(Event).where(Event.id == event_id)).scalar()
    if event:
        result = db.session.execute(
            db.select(Category).where(Category.name == data.get("category"))
        )
        category = result.scalar()

        result2 = db.session.execute(
            db.select(Address).where(
                Address.complement == data.get("location")
            )  # THIS DOESNT REALLY MATTER, WE'LL BE USING AN API FOR THIS LATER.
        )
        address = result2.scalar()

        current_user_id = get_jwt_identity()

        parsed_start_date = parse_date("start-date")
        parsed_end_date = parse_date("end-date")

        event.title = data.get("title")
        event.category_id = category.id
        event.description = data.get("description")
        event.event_start_date = parsed_start_date
        event.event_end_date = parsed_end_date
        event.location_id = address.id
        event.entry_fee = data.get("entry-fee")
        event.host_id = current_user_id
        event.is_private = data.get("is_private")

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
