"""Generate CSVs of random data for Friender."""

import csv
from dataclasses import field
from itertools import permutations
from faker import Faker
from random import choice, sample

USERS_CSV_HEADERS = ['username','password','email','first_name','last_name','location','friend_radius','hobbies', 'interests','image_url']
MATCHES_CSV_HEADERS = ['user_id','match_id']
NUM_USERS = 300
NUM_FOLLWERS = 5000
HOBBIES = ['Swimming', 'Running', 'Photography', 'Playing musical instruments', 'Modeling', 'Painting', 'Candy Making', 'Chess', 'Beer Tasting', 'Crossfit', 'Brazillian Jiu Jitsu', 'Coding', 'Video Games', 'Gardening', 'Yoga', 'Judo', 'Comedy Shows', 'Movies']
INTERESTS = ['Nature', 'History', 'Gaming', 'Travel', 'Art', 'Music', 'Outdoors']

fake = Faker()

# Generate random profile image URLs to use for users

image_urls = [
    f"https://randomuser.me/api/portraits/{kind}/{i}.jpg"
    for kind, count in [("lego", 10), ("men", 100), ("women", 100)]
    for i in range(count)
]

with open('generator/users.csv', 'w') as users_csv:
    users_writer = csv.DictWriter(users_csv, fieldnames=USERS_CSV_HEADERS)
    users_writer.writeheader()

    for i in range(NUM_USERS):
        users_writer.writerow(dict(
            username=fake.user_name(),
            password='$2b$12$Q1PUFjhN/AWRQ21LbGYvjeLpZZB6lfZ1BPwifHALGO6oIbyC3CmJe',
            email=fake.email(),
            first_name=fake.first_name(),
            last_name=fake.last_name(),
            location=choice(['94605', '95119', '94540', '94701', '94016', '94509', '94507']),
            friend_radius=100,
            hobbies=sample(HOBBIES, 5),
            interests=sample(INTERESTS,3),
            image_url=choice(image_urls),
        ))

# Generate matches.csv from random pairings of users

# with open('generator/matches.csv', 'w') as matches_csv:
#     all_pairs = list(permutations(range(1, NUM_USERS + 1), 2))

#     users_writer = csv.DictWriter(matches_csv, fieldnames=MATCHES_CSV_HEADERS)
#     users_writer.writeheader()

#     for followed_user, matcher in sample(all_pairs, NUM_FOLLWERS):
#         users_writer.writerow(dict(
#             user_id=followed_user,
#             match_id=matcher
#         ))