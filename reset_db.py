from server import db, User
db.drop_all()
db.create_all()
db.session.add(User(name='admin', password=b'$2b$10$MuqRlqo2SC97TU3Z6BmBBe7vrs9ARVBBOv3WmfjquY9MXwbyshxfy', admin=True))
db.session.add(User(name='bra', password=b'$2b$10$9kmb6L0/J6MxBp8HK2EJ3eE/rgx.HC1pjIvO3YPVZwfn2h1yGslXS'))
db.session.commit()
