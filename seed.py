"""Seed database with sample data from CSV Files."""

from csv import DictReader
from app import db

from models import User, Match, Reject, Message

db.session.rollback()
db.drop_all()
db.create_all()

with open('generator/users.csv') as users:
    db.session.bulk_insert_mappings(User, DictReader(users))

# with open('generator/matches.csv') as matches:
#     db.session.bulk_insert_mappings(Match, DictReader(matches))

# with open('generator/rejects.csv') as rejects:
#     db.session.bulk_insert_mappings(Reject, DictReader(rejects))

# with open('generator/messages.csv') as messages:
#     db.session.bulk_insert_mappings(Message, DictReader(messages))



db.session.commit()

