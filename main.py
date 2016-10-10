import os
import jinja2
import webapp2
import re
import hmac
import hashlib
import string
import random
import secret_ky  # secret used for hashed password.

from google.appengine.ext import db

# JINJA SETUP #

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(
    loader=jinja2.FileSystemLoader(template_dir), autoescape=True)
"""set up of Jinja templates"""

# DATABASES #


def blog_key(name='default'):
    return db.Key.from_path('blogs', name)
    """The Parent blog key."""


class Posts(db.Model):

    """ Database for Post Entries

    This Database stores and holds all Posts that were created.

    Attributes:
        subject: The subject of the post.
        content: The content of the post.
        created: Returns date when the post was created.
        last_modified: Last time post was changed.
        author: user id of the person who wrote the post.
        liked: Indicates whether post was liked by the current user.

    """

    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now_add=True)
    author = db.StringProperty()
    liked = db.BooleanProperty()  # for liked posts


class Comments(db.Model):

    """ Database for Comments

    This Database stores all comments made on posts.

    Attributes:
        com_content: The content of the comment.
        author: The author of the comment, used to relate to User Database
        post_id: The id of the post that was commented on.
        created: The date the comment was created.

    """

    com_content = db.TextProperty(required=True)
    author = db.StringProperty(required=True)
    post_id = db.StringProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)


class Likes(db.Model):

    """ Database for Likes on posts

    This Database stores any likes that were made on a post.

    Attributes:
        user: The id of the user who created the post.
        post_id: The id of the post that was liked.

    """

    user = db.StringProperty(required=True)
    post_id = db.StringProperty(required=True)

# The User database to store our user credentials.##


class User(db.Model):

    """ Database for Users

    This Database stores all created users.

    Attributes:
        user: The users name
        password: Stores a hashed password using sha256.

    """

    user = db.StringProperty(required=True)
    password = db.StringProperty(required=True)
    email = db.StringProperty(required=False)

    @classmethod
    def get_name(cls, name):
        """Used in login class method to find user name in User database

        Args:
            name: The users name.

        Returns:
            current_user: The entry in the User database that matches the name.

        """

        current_user = db.GqlQuery(
            "SELECT * FROM User WHERE user=:1", name).get()
        return current_user

    @classmethod
    def by_id(cls, uid):
        """Query the user database and return the user id.

        Args:
            uid: the user id.

        Returns:
            user.user: The user name of the user from the User database.

        """

        user = User.get_by_id(uid)
        return user.user

    @classmethod
    def register(cls, name, pw, email=None):
        """Take the user credentials entered, hashes password,
            prepares to register user.

            Args:
                name: the user name.
                password: the user entered password.
                email: the user entered email, it is optional.

            Returns:
                An entry prepared to pass the inputted
                information into User database.

        """

        pw_hash = create_hash_pw(name, pw)
        return User(user=name, password=pw_hash, email=email)

    @classmethod
    def login(cls, name, pw):
        """Performs the task of logging in and validating a user.

        Args:
            name: the inputted name
            password: the inputted password

        Returns:
            current_user: The user from the User database.

        """
        current_user = cls.get_name(name)
        if current_user and valid_pw(name, pw, current_user.password) == True:
            return current_user
        else:
            print "login-failed"


# USER SIGNUP #

def make_salt(length=5):
    """Creates salt to be used in user password.

        Args:
            length = set at 5 characters.

        Returns:
            A random string of 5 characters.

    """

    s = ''.join(random.choice(string.letters) for x in xrange(length))
    return str(s)


def create_hash_pw(name, pw, salt=None):
    """Create a hashed password to pass in to database.

        Args:
            name: the entered user name.
            pw: the user entered password.
            salt: either the salt created in the
            make_salt function or an entered salt.


        Returns:
            A hashed password split by a '|'.
            The front end is the salt for the password.

    """

    if not salt:
        pwsalt = make_salt()
    else:
        pwsalt = salt
    pwhash = hashlib.sha256(name + pw + pwsalt).hexdigest()
    return "%s|%s" % (pwsalt, pwhash)


def valid_pw(name, pw, h):
    """Validates password.

        Args:
            name: the entered user name.
            pw: the user entered password.
            h: the hashed password string

        Returns:
            A Boolean, True if the password is valid or False otherwise.

    """
    salt_hash = h.split("|")[0]
    check_pw = create_hash_pw(name, pw, salt_hash)
    return h == check_pw


USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")


def valid_username(username):
    """Checks if username entered is a valid format.

        Args:
            username: The user entered user name.

        Returns:
            if valid returns True.

    """

    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")


def valid_password(password):
    """Checks if password entered is a valid format.

        Args:
            password: The user entered password.

        Returns:
            if valid returns True.

    """

    return password and PASS_RE.match(password)

EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')


def valid_email(email):
    """Checks if email entered is a valid format.

        Args:
            password: The user entered password.

        Returns:
            if valid returns False.

    """

    return not email or EMAIL_RE.match(email)


# HANDLERS #

class Handler(webapp2.RequestHandler):

    """ Handler for rendering pages

    All other Handlers inherit the methods in here.

    """

    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

# The User Handler that adds to the base handler and adds cookies.
# All other Handlers will inherits the methods in here.


class UserHandler(Handler):

    """ Handler for rendering pages, inherits from Handler.

    Adds to Handler class and adds cookie methods.

    """

    def create_secure_val(self, value):
        """Creates the hashed string to send to user_id cookie.

        Args:
            value: the user id.

        Returns:
            A hashed user string to be passed to the cookie.

        """

        hashu = hashlib.sha256(value + secret_ky.secret).hexdigest()
        return "%s|%s" % (value, hashu)

    def check_secure_val(self, value):
        """Checks the string pulled from the cookie and splits off the user_id.

        Args:
            value: the string from the user_id cookie.

        Returns:
            if valid returns the user_id, if not valid returns None.

        """

        h_value = value.split("|")[0]
        if value == self.create_secure_val(h_value):
            return h_value
        else:
            return None

    def new_cookie(self, uid):
        """Takes created hashed string and sets the user_id cookie.

        Args:
            uid: the user id.

        Returns:
            sets the user_id cookie.

        """

        user_id_cookie = self.create_secure_val(uid)
        return self.response.headers.add_header('Set-Cookie',
                                                'user_id=%s; PATH=/'
                                                % str(user_id_cookie))

    def read_secure_cookie(self):
        """Pulls the user_id cookie and validates if it is valid.

        Args:
            None

        Returns:
            if valid returns the current users id.

        """

        user_str = self.request.cookies.get('user_id')
        cookie_val = self.check_secure_val(user_str)
        if cookie_val and self.check_secure_val(user_str):
            return cookie_val

    def login_user(self, user):
        """Uses new cookie and sets cookie methods to log in user

        Args:
            user: the user entry in User database.

        Returns:
            the new user cookie.

        """
        user_id = str(user.key().id())
        self.new_cookie(user_id)


class Landing(UserHandler):

    """Main landing page Handler.

        """

    def get(self):
        self.render("front.html")

# BLOG HANDLERS


class BlogMain(UserHandler):

    """The Main Blog Page that displays the 10 most recent Blog entries.

    """

    def get(self):
        """Sets the Main Blog Page.

        Returns:
            renders the blog.html for the page.
        """

        user_id = self.read_secure_cookie()
        if user_id:
            username = User.by_id(int(user_id))
        else:
            username = None
        entries = db.GqlQuery(
            "SELECT * FROM Posts ORDER BY created DESC LIMIT 10")
        liked = db.GqlQuery("SELECT * FROM Likes")
        # checks if any entries are either the current users post, they liked
        # the post or didn't like it.#
        for e in entries:
            for l in liked:
                if l.user == e.author:
                    e.liked = None
                    e.put()
                    break
                elif l.post_id == str(e.key().id()):
                    e.liked = True
                    e.put()
                    break
                else:
                    e.liked = False
                    e.put()

        self.render(
            "blog.html", posts=entries, username=username, user_id=user_id)


class NewPost(UserHandler):

    """Handler for creating new posts.

    """

    def get(self):
        """Sets New Post page.

        Returns:
            renders newpost.html for the page.
        """

        self.render("newpost.html")

    def post(self):
        """Posts on the New Post page.

        Returns:
            if valid enters a new post or re renders with errors.
        """
        subject = self.request.get("subject")
        content = self.request.get("content")
        author = str(self.read_secure_cookie())
        print author

        if author == "None":  # Checks if there is a user.
            self.redirect("/")

        # Checks to see if there is a user and subject.
        elif subject and content:
            current_post = Posts(
                parent=blog_key(), subject=subject,
                content=content, author=author)
            current_post.put()
            self.redirect("/%s" % str(current_post.key().id()))

        else:
            error = "Please enter a subject and content!"
            self.render(
                "newpost.html", subject=subject, content=content, error=error)


class Post(UserHandler):

    """The Handler to display an individual post.

    """

    def get_comments(self, blog_key):
        """Finds all comments on a particular post.

        Args:
            blog_key: The id of the post that is being queried.

        Returns:
            all comments that match the post
        """

        post_comments = db.GqlQuery(
            "SELECT * FROM Comments WHERE post_id=:1",
            str(blog_key.key().id()))
        return post_comments

    def get(self, post_id):
        """Sets Individual Post page.

        Returns:
            renders permalink.html for the page.
        """

        key = db.Key.from_path("Posts", int(post_id), parent=blog_key())
        post = db.get(key)
        # Retrieves comments on the post#
        post_comments = self.get_comments(post)
        user_id = self.read_secure_cookie()
        if user_id:
            username = User.by_id(int(user_id))
        else:
            username = None
        isliked = db.GqlQuery(
            "SELECT * FROM Likes WHERE user=:1 AND post_id=:2",
            str(user_id), str(post_id)).get()

        # Checking against likes to see if current user has liked post. #
        if isliked:
            liked = True
        else:
            liked = False

        self.render("permalink.html", post=post,
                    post_comments=post_comments,
                    username=username, liked=liked)

    def post(self, post_id):
        """Posts comments on the New Post page.

            Args:
                post_id: The id of the post.

            Returns:
                if without errors it enter the comment in to Comment database.
                If with error it re renderts the page with an error.
        """
        com_content = self.request.get("com_content")
        author = str(self.read_secure_cookie())
        key = db.Key.from_path("Posts", int(post_id), parent=blog_key())
        post = db.get(key)
        post_id = str(post.key().id())

        post_comments = self.get_comments(post)
        user_id = int(self.read_secure_cookie())
        username = User.by_id(user_id)

        if not user_id:  # Checking for a user
            error = "Sorry only logged in users can post comments"
            self.render("permalink.html", post=post,
                        post_comments=post_comments,
                        username=username, error=error)

        elif com_content:  # Checks to see if comment has content.
            current_comment = Comments(
                com_content=com_content, author=author, post_id=post_id)
            current_comment.put()
            self.redirect("/%s" % post_id)
        else:
            error = "Sorry the comment can not be blank"
            self.render("permalink.html", post=post,
                        post_comments=post_comments,
                        username=username, error=error)


class EditPost(UserHandler):

    """The Handler for editing a post and possibly save the edited post.

    """

    def get(self, post_id):
        """Sets Edit Post page.

            Args:
                post_id: the id of the post.

            Returns:
                renders editpost.html for the page.
        """
        key = db.Key.from_path("Posts", int(post_id), parent=blog_key())
        post = db.get(key)
        post_id = post.key().id()
        subject = post.subject
        content = post.content
        user_id = int(self.read_secure_cookie())
        username = User.by_id(user_id)

        self.render("editpost.html", subject=subject,
                    content=content, username=username, post_id=str(post_id))

    def post(self, post_id):
        """Sets Edit Post page.

            Args:
                post_id: the id of the post.

            Returns:
                if without error saves changes to the post entry.
                If with error re renders editpost with an error.
        """
        key = db.Key.from_path("Posts", int(post_id), parent=blog_key())
        current_post = db.get(key)
        post_id = current_post.key().id()
        author = current_post.author
        subject = self.request.get("subject")
        content = self.request.get("content")
        user_id = int(self.read_secure_cookie())
        username = User.by_id(user_id)

        # Saves edits that you made on the post or returns an error if you are
        # not the author. #
        if current_post.author == str(user_id):
            current_post.subject = subject
            current_post.content = content
            current_post.put()
            self.redirect("/%s" % str(post_id))

        else:
            error = "Sorry you cannot edit others posts"
            self.render("editpost.html", post_id=post_id, subject=subject,
                        content=content, username=username, error=error)


class EditComments(UserHandler):

    """The Handler edits a comment.

    """

    def get(self, comment_id):
        """Sets Edit Comment page.

            Args:
                comment_id: the id of the comment.

            Returns:
                renders editcomment.html for the page.
        """
        key = db.Key.from_path("Comments", int(comment_id))
        current_comment = db.get(key)
        com_content = current_comment.com_content
        post_id = current_comment.post_id
        user_id = int(self.read_secure_cookie())
        username = User.by_id(user_id)
        comment_id = current_comment.key().id()

        self.render("editcomment.html", comment_id=comment_id,
                    com_content=com_content,
                    post_id=post_id, username=username)

    def post(self, comment_id):
        """Posts Edit Comment page.

            Args:
                comment_id: the id of the comment.

            Returns:
                if without error will update comment entry
                and direct back to post.
                If with error will direct back to the post with and error.
        """
        key = db.Key.from_path("Comments", int(comment_id))
        current_comment = db.get(key)
        com_content = self.request.get("com_content")
        post_id = current_comment.post_id
        user_id = int(self.read_secure_cookie())
        username = User.by_id(user_id)
        comment_id = current_comment.key().id()

        if not com_content:  # Check to see if comment is now blank.
            error = "Comment cannot be blank."
            self.render("editcomment.html", comment_id=comment_id,
                        com_content=com_content, post_id=post_id,
                        username=username, error=error)

        # Must be author of comment.
        elif str(user_id) == current_comment.author:
            current_comment.com_content = com_content  # New comment content.
            current_comment.put()  # saving comment.
            self.redirect("/%s" % str(post_id))

        else:
            error = "Sorry you cannot edit others comments."
            self.render("editcomment.html", comment_id=comment_id,
                        com_content=com_content, post_id=post_id,
                        username=username, error=error)


class DeleteComments(UserHandler):

    """This Handler will delete a comment.
    """

    def get(self, comment_id):
        """Sets Delte Comment.

            Args:
                comment_id: the id of the comment.

            Returns:
                If without error will delete entry and return to post page.
                If with error will re render post page with error message.
        """
        key = db.Key.from_path("Comments", int(comment_id))
        current_comment = db.get(key)
        comment_id = current_comment.key().id()
        com_content = current_comment.com_content
        user_id = int(self.read_secure_cookie())
        username = User.by_id(user_id)
        post_id = current_comment.post_id

        # Must be author of the comment.
        if current_comment.author == str(user_id):
            db.delete(current_comment)  # delete the comment entry.
            self.redirect("/%s" % str(post_id))

        else:
            error = "Sorry you cannot delete others comments"
            self.render("editcomment.html", comment_id=comment_id,
                        com_content=com_content, post_id=post_id,
                        username=username, error=error)


class DeletePost(UserHandler):

    """The Handler that will delete a post from the database.

    """

    def get(self, post_id):
        """Deletes the post

            Args:
                post_id: the id of the post.

            Returns:
                if without error sends user back to the main blog page.
                If with error re renders editpost page with an error.
        """
        key = db.Key.from_path("Posts", int(post_id), parent=blog_key())
        current_post = db.get(key)
        user_id = int(self.read_secure_cookie())
        username = User.by_id(user_id)

        if current_post.author == str(user_id):
            db.delete(current_post)
            self.redirect("/blog")
        else:
            error = "Sorry you cannot delete others posts"
            self.render("editpost.html", post_id=post_id,
                        subject=current_post.subject,
                        content=current_post.content,
                        username=username, error=error)


class LikePost(UserHandler):

    """The Handler that will like a post and a like into Like database.

    """

    def get(self, post_id):
        """Likes the post

            Args:
                post_id: the id of the post.

            Returns:
                if without error sends user back to the post.
                If with error re renders editpost page with an error.
        """
        key = db.Key.from_path("Posts", int(post_id), parent=blog_key())
        current_post = db.get(key)
        post_id = current_post.key().id()
        user_id = int(self.read_secure_cookie())
        username = User.by_id(user_id)

        # If you are not the author you can like the post and new entry on Like
        # database is made. #
        if current_post.author != str(user_id):
            like_post = Likes(user=str(user_id), post_id=str(post_id))
            like_post.put()
            self.redirect("/%s" % post_id)
        else:
            # Sends you to Edit page#
            error = "Sorry you cannot like your own post."
            self.render("editpost.html", post_id=post_id,
                        subject=current_post.subject,
                        content=current_post.content,
                        username=username, error=error)


class UnlikePost(UserHandler):

    """The handler to unlike a particular post.

    """

    def get(self, post_id):
        """Unlikes the post

            Args:
                post_id: the id of the post.

            Returns:
                if without error sends user back to the post.
                If with error re renders editpost page with an error.
        """
        key = db.Key.from_path("Posts", int(post_id), parent=blog_key())
        current_post = db.get(key)
        post_id = current_post.key().id()
        user_id = int(self.read_secure_cookie())
        username = User.by_id(user_id)
        liked_post = db.GqlQuery(
            "SELECT * FROM Likes WHERE user=:1 and post_id=:2",
            str(user_id), str(post_id)).get()

        if current_post != str(user_id):
            # Removes the liked entry from the database. #
            db.delete(liked_post)
            self.redirect("/%s" % post_id)
        else:
            error = "Sorry you cannot unlike your own post."
            self.render("editpost.html", subject=current_post.subject,
                        content=current_post.content,
                        username=username, error=error)

# USER HANDLERS


class SignUp(UserHandler):

    """The Sign Up Page Handler that allows a user to sign up
    """

    def get(self):
        """Gets the Signup page

            Returns:
                The signup page
        """
        self.render("signup.html")

    def post(self):
        """Posts to the Signup database

            Returns:
                If without error signs up the user and sets the cookie.
                If with error re renders page with an error message.
        """
        have_error = False
        username = self.request.get('username')
        password = self.request.get('password')
        verify = self.request.get('verify')
        email = self.request.get('email')

        params = dict(username=username,
                      email=email)
        # Error checking
        if not valid_username(username):
            params['error'] = "That's not a valid username."
            have_error = True
        else:
            dup_user = db.GqlQuery(
                "SELECT * FROM User WHERE user=:1", username).get()
            if dup_user:
                params['error'] = "That username already exists."
                have_error = True

        if not valid_password(password):
            params['error'] = "That wasn't a valid password."
            have_error = True
        elif password != verify:
            params['error'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(email):
            params['error'] = "That's not a valid email."
            have_error = True

        # Generate pages
        if have_error:
            self.render('signup.html', **params)
        else:
            current_user = User.register(
                name=username, pw=password, email=email)
            current_user.put()  # Enters new user in to User database.
            self.login_user(current_user)  # sets the user_id cookie.

            self.redirect('/welcome')


class Welcome(UserHandler):

    """The Welcome Page Handler that acknowledges sucessfully sign up or login.
    """

    def get(self):
        """Gets the Welcome page

            Returns:
                The welcome page
        """

        user_id = int(self.read_secure_cookie())
        username = User.by_id(user_id)

        self.render("welcome.html", username=username)


class Login(UserHandler):

    """The Login Page Handler that allows existing users to sign in.
    """

    def get(self):
        """Gets the Login page.

            Returns:
                renders the login page.
        """

        self.render("login.html")

    #
    def login_now(self, name, password):
        """check the username and password

            Args:
                name: Entered username
                password: Entered password

            Returns:
                if without error sets user_id cookie
                and directs to welcome page.
                If with error re renders page with error message.

        """

        current_user = User.login(name=name, pw=password)
        if current_user:
            self.login_user(current_user)
            self.redirect('/welcome')

        else:
            error_msg = "Sorry, something didn't match, try again."
            self.render("login.html", name=name, error=error_msg)

    def post(self):
        """Logs in user

            Returns:
                logs in user and sets cookie.

        """

        name = self.request.get('name')
        password = self.request.get('password')

        self.login_now(name, password)


class Logout(UserHandler):

    """The Logout Handler that logs the user out and clears the cookie.
    """

    def get(self):
        """Logs out user

            Returns:
                clears cookie and returns to landing page.

        """

        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')
        self.redirect('/')


app = webapp2.WSGIApplication([
    ('/', Landing),
    ('/blog', BlogMain),
    ('/newpost', NewPost),
    ('/([0-9]+)', Post),
    ('/signup', SignUp),
    ('/welcome', Welcome),
    ('/login', Login),
    ('/logout', Logout),
    ('/edit/([0-9]+)', EditPost),
    ('/editcomment/([0-9]+)', EditComments),
    ('/deletecomment/([0-9]+)', DeleteComments),
    ('/delete/([0-9]+)', DeletePost),
    ('/like/([0-9]+)', LikePost),
    ('/unlike/([0-9]+)', UnlikePost),
], debug=True)
