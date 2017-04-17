import os
import re
import webapp2
import jinja2
import hashlib
import hmac
import string
import random
import time
from google.appengine.ext import db

########################################################

######################   Global   ######################

########################################################

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape = True)

#Retrieved from grc.com
secret = "wGuA4zMzr465NsBeDSfpF5u3CC1LsD8JYJiVrsCOpWookykZzMVtV5BHX1g9Ta6"

######   Globab render_str function   #####

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

######   Create a secure value   #####
def create_secure_val(val):
    return val + "|" + hmac.new(secret, val).hexdigest()

# Check a secure value
def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == create_secure_val(val):
        return val

#####   Password Security Methods   #####

# Create random salt
def create_salt():
    return ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(9))    

# Create password hash
def create_pw_hash(email, pw, salt = None):
    if not salt:
        salt = create_salt()
    h = hashlib.sha256(''.join([email, pw, salt])).hexdigest()
    return salt + "|" + h

# Verify password hash
def validate_pw(email, pw, h):
    salt = h.split('|')[0]   # Should this be 0?
    return h == create_pw_hash(email, pw, salt)

########################################################

#################### Master Handler ####################

########################################################

#MasterHandler Class
class MasterHandler(webapp2.RequestHandler):

#Jinja Methods
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

#Cookie Security Methods

    # Set a secure cookie
    def set_secure_cookie(self, name, val):
        cookie_val = create_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    # Check a secure cookie
    def check_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    # Set cookie upon user login
    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    # Reset cookie upon user logout
    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    # Obtain user from cookie when pages are initialized
    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.check_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))

########################################################

################### Database Models ####################

########################################################

#Database to store user information
class User(db.Model):

    email = db.EmailProperty(required=True)
    name = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)

    #Get user by e-mail
    @classmethod
    def by_email(cls, email):
        return User.all().filter("email =", email).get()

    #Get user by id
    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid)

    #Get user by name
    @classmethod
    def by_name(cls, uid):
        u = User.all().filter('name =', name).get()
        return u

    #Create a new user object
    @classmethod
    def register(cls, email, name, pw):
        pw_hash = create_pw_hash(email, pw)
        return User(email = email,
                    name = name,
                    pw_hash = pw_hash)

    #Login user
    @classmethod
    def login(cls, email, pw):
        u = cls.by_email(email)
        if u and validate_pw(email, pw, u.pw_hash):
            return u

#Database to store blog post information
class Post(db.Model):

    title = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now = True)
    user_id = db.IntegerProperty(required=True)
    # likes = db.IntegerProperty(default=0)
    user = db.StringProperty(required=True)

    #Put line breaks in post content
    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p=self)

#Database to store post comments
class Comment(db.Model):

    comment = db.StringProperty(required=True)
    post = db.StringProperty(required=True)
    commentor = db.StringProperty(required=True)

    # @classmethod
    # def render(self):
    #     self.render("comment.html")

# #Database to store post likes
# class Like(db.Model):

#   user_id = db.IntegerProperty(required=True)
#     post_id = db.IntegerProperty(required=True)

#     def getUserName(self):
#         user = User.by_id(self.user_id)
#         return user.name


########################################################

#################### Page Handlers #####################

########################################################


##############    Front Page    #############

class FrontPage(MasterHandler):
    def get(self):
        # Retrieve all blog posts
        posts = db.GqlQuery("SELECT * FROM Post ORDER BY created DESC limit 10")

        #Validate user
        if self.user:
            self.render('dashboard.html', user = self.user.name, posts=posts)
        else:
            self.redirect('/')

##############    SignUp Page    #############

class SignUpPage(MasterHandler):
    def get(self):
        self.render("signup.html", error=None)

    def post(self, error=None):
        self.email = self.request.get("email")
        self.name = self.request.get("name")
        self.password = self.request.get("password")
        self.confirm_password = self.request.get("confirm-password")

        params = dict(name = self.name,
                    email = self.email)

        # Validate password against confirm-password
        if self.password != self.confirm_password:
            error = "Your passwords do not match."
        # Validate email format
        elif not (re.match(
                  r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)",
                  self.email)):
            error = "Please enter a valid email address."
        # Check if e-mail already exists in database
        elif User.by_email(self.email):
            error = "A user with that email already exists."
        # If user passes all validations, proceed with registration
        else:
            #Create the new User object and store in database
            u = User.register(self.email, self.name, self.password)
            u.put()

            #Set the cookie
            self.login(u)
            self.redirect("/dashboard")
        
        self.render("signup.html", error=error, **params)

##############    Login Page    #############

class LoginPage(MasterHandler):
    def get(self):
        self.render("login.html", error=None)

    def post(self, error=None):
        email = self.request.get('email')
        password = self.request.get('password')

         # Check if e-mail exists in database
        u = User.login(email, password)
        if u:
            self.login(u)
            self.redirect("/dashboard")
        else:
            error = "Invalid login information."
            self.render("login.html", error=error)

##############    Dashboard Page    #############

class DashboardPage(MasterHandler):
    def get(self):
        # Retrieve all blog posts
        posts = db.GqlQuery("SELECT * FROM Post ORDER BY created DESC limit 10")

        #Validate user
        if self.user:
            self.render('dashboard.html', user = self.user.name, posts=posts)
        else:
            self.redirect('/login')

    def post(self, post_id):
        key = db.Key.from_path('Post', int(post_id))
        post = db.get(key)
        if not post:
            self.error(404)
            return
        
        comment = self.request.get('comment')

        if comment:
            commentor = self.user.name
            c = Comment(comment=comment, post=post_id,
                        commentor = commentor)
            c.put()

            self.redirect('/dashboard')

##############    Logout Page    #############

class LogOutPage(MasterHandler):
    def get(self):
        self.logout()
        self.redirect("/")

##############    New Post Page    #############

class NewPostPage(MasterHandler):
    def get(self):
        self.render('newpost.html')

    def post(self):
        title = self.request.get('title')
        content = self.request.get('content')

        if title and content:
            p = Post(title=title, content=content,
                    user_id = self.user.key().id(),
                    user = self.user.name)
            p.put()
            self.redirect('/post/%s' % str(p.key().id()))
        else:
            error = "You need both a title and some content to create a new post."
            self.render("newpost.html", title=title, 
                        content=content, error=error)

##############    View Post Page    #############

class ViewPostPage(MasterHandler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id))
        post = db.get(key)

        if not post:
            return self.error(404)

        self.render("permalink.html", post=post)

##############    Edit Post Page    #############

class EditPostPage(MasterHandler):
    def get(self, post_id):

        # Retrieve all blog posts
        posts = db.GqlQuery("SELECT * FROM Post ORDER BY created DESC limit 10")

        if self.user:
            key = db.Key.from_path('Post', int(post_id))
            post = db.get(key)
            if post.user_id == self.user.key().id():
                self.render("editpost.html", title=post.title,
                            content=post.content)
            else:
                error = "You do not have access to edit this post."
                self.render("dashboard.html", user = self.user.name,
                    posts=posts, error=error)


    def post(self, post_id):

        if not self.user:
            self.redirect('/dashboard')

        title = self.request.get('title')
        content = self.request.get('content')

        if title and content:
            key = db.Key.from_path('Post', int(post_id))
            post = db.get(key)
            post.title = title
            post.content = content
            post.put()
            self.redirect('/post/%s' % post_id)
        else:
            error = "You need both a title and some content to create a new post."
            self.render("editpost.html", title=title,
                        content=content, error=error)

##############    Delete Post Page    #############

class DeletePostPage(MasterHandler):
    def get(self, post_id):

        # Retrieve all blog posts
        posts = db.GqlQuery("SELECT * FROM Post ORDER BY created DESC limit 10")

        if self.user:
            key = db.Key.from_path('Post', int(post_id))
            post = db.get(key)
            if post.user_id == self.user.key().id():
                post.delete()
                error = "Your post has been deleted."
                self.render("deletepost.html", error=error)
            else:
                error = "You do not have access to delete this post."
                self.render("dashboard.html", user = self.user.name,
                    posts=posts, error=error)
        else:
            self.redirect("/login?error=You need to be logged, in order" +
                          " to delete your post!!")

##############    webapp2 Routes    #############

app = webapp2.WSGIApplication([
    ("/", FrontPage),
    ("/signup", SignUpPage),
    ("/login", LoginPage),
    ("/logout", LogOutPage),
    ("/dashboard", DashboardPage),
    ("/newpost", NewPostPage),
    ("/post/([0-9]+)", ViewPostPage),   
    ("/post/edit/([0-9]+)", EditPostPage),
    ("/post/delete/([0-9]+)", DeletePostPage)
    #("/post/(.*)/comment/(.*)", ViewCommentPage),
    #("/post/(.*)/comment", CreateCommentPage),
    #("/post/(.*)/comment/(.*)/edit", EditCommentPage),
    #("/post/(.*)/comment/(.*)/delete", DeleteCommentPage)
], debug=True)
