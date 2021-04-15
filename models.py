#!/usr/bin/env python3
"""The database part"""

from datetime import datetime
from peewee import *
from flask_bcrypt import generate_password_hash
from flask_login import UserMixin

import csv, random


db = PostgresqlDatabase('my_app', user='postgres', password='secret',
                           host='10.1.0.9', port=5432)

class User(UserMixin, Model):
    """Table for user info"""
    username = CharField(unique=True)
    email = CharField(unique=True)
    password = CharField(max_length=100)
    joined_at = DateTimeField(default=datetime.now)
    is_admin = BooleanField(default=False)

    class Meta:
        """Configuration attributes"""
        database = db
        order_by = ('-joined_at',)

    @classmethod
    def create_user(cls, username, email, password, admin=False):
        """Create user"""
        try:
            # transaction is to prevent a user from being half created.
            # Tries it out and if it doesn't work undoes everything
            with db.transaction():
                cls.create(
                    username=username,
                    email=email,
                    password=generate_password_hash(password),
                    is_admin=True)
        except IntegrityError:
            raise ValueError("User already exists")

    @classmethod
    def create_user_dict(cls, entry_dict):
        """Create user from dictionary"""
        try:
            with db.transaction():
                entry_dict["password"]=generate_password_hash(entry_dict["password"],4)
                cls.create(**entry_dict)
        except IntegrityError:
            pass


def read_Users_from_CSV():
    """Read the CSV and call add to database function"""
    with open('User_list.csv', newline='') as csvfile:
        UserReader = csv.DictReader(csvfile, delimiter=',')
        lines = list(UserReader)
        for line in lines:
            User.create_user_dict(line)


class Journal(UserMixin, Model):
    """Define product categories"""
    entry_id = AutoField()
    date_created = DateTimeField()
    title = CharField(max_length=255, unique=True)
    date = DateField()
    time_spent = IntegerField(default=0)
    Characters = TextField(unique=False)
    Play = TextField()
    tags = CharField(max_length=255, unique=False)
    owner = CharField(max_length=255, unique=False)

    class Meta:
        """Configuration attributes"""
        database = db

    @classmethod
    def add_entry(cls, title, date, time_spent, learned, remember,
                  tags, owner):
        """Add an entry to database"""
        entry_dict = {}
        entry_dict['date_created'] = datetime.strftime(datetime.now(),
                                                       "%d.%m.%Y %H:%M:%S")
        entry_dict['title'] = title
        entry_dict['date'] = date
        entry_dict['time_spent'] = time_spent
        entry_dict['Characters'] = learned
        entry_dict['Play'] = remember
        entry_dict['tags'] = tags
        entry_dict['owner'] = owner
        try:
            cls.create(**entry_dict)
            # print(f"\nA new entry was added to the database:\n"
            #       f"title: {title} Date: {date} Time Spent: {time_spent}"
            #       f" Learned: {learned} Remember: {remember} tags: {tags}\n")
        except IntegrityError:
            pass

    @classmethod
    def add_dict_entry(cls, entry_dict):
        """Add a dictionary entry to database"""
        try:
            cls.create(**entry_dict)
        except IntegrityError:
            pass


def read_shakespeare_from_CSV():
    """Read the CSV and call add to database function"""
    with open('Shakespeare.csv', newline='') as csvfile:
        playreader = csv.DictReader(csvfile, delimiter=',')
        lines = list(playreader)
        PlayerLines = ''
        Characters = ''
        newplay = {}
        lastplay = lines[0]['Play']

        for line in lines:
            if line['Play'] != lastplay:
                newplay['date_created'] = datetime.strftime(datetime.now(),
                                                               "%d.%m.%Y %H:%M:%S")
                newplay['title'] = lastplay
                d = random.randint(1,29)
                m = random.randint(1,12)
                y = random.randint(1589,1613)
                newplay['date'] = f'{y}-{m}-{d}'
                # newplay['date'] = datetime.strftime(datetime.now(),
                #                                                "%Y-%m-%d")
                newplay['time_spent'] = random.randint(111,999)
                newplay['Characters'] = Characters
                newplay['Play'] = PlayerLines
                newplay['tags'] = 'Shakespeare, Play, Poetry'
                newplay['owner'] = 'Sebastiaan'
                Journal.add_dict_entry(newplay)
                PlayerLines = ''
                Characters = ''
                lastplay = line['Play']
            if len(Characters) == 0:
                Characters = line['Player']
            elif line['Player'] not in Characters:
                Characters = f"{Characters}, {line['Player']}"
            if len(PlayerLines) == 0:
                PlayerLines = line['PlayerLine']
            elif len(PlayerLines) < 1000:
                PlayerLines = f"{PlayerLines} {line['PlayerLine']}"

def initialize():
    """Create the database if it doesn't exist"""
    db.connect()
    db.create_tables([User, Journal], safe=True)
    db.close()
