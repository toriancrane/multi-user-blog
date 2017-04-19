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
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                            autoescape = True)

#Retrieved from grc.com
secret = "wGuA4zMzr465NsBeDSfpF5u3CC1LsD8JYJiVrsCOpWookykZzMVtV5BHX1g9Ta6"

def render_str(template, **params):
    """ Global render_str function """
    t = jinja_env.get_template(template)
    return t.render(params)

def create_secure_val(val):
    """ Create a secure value """
    return val + "|" + hmac.new(secret, val).hexdigest()

def check_secure_val(secure_val):
    """ Check a secure value """
    val = secure_val.split('|')[0]
    if secure_val == create_secure_val(val):
        return val

#####   Password Security Methods   #####

def create_salt():
    """ Create random salt """
    return ''.join(random.SystemRandom().choice(
        string.ascii_uppercase + string.digits) for _ in range(9))    

def create_pw_hash(email, pw, salt = None):
    """ Create password hash """
    if not salt:
        salt = create_salt()
    h = hashlib.sha256(''.join([email, pw, salt])).hexdigest()
    return salt + "|" + h

def validate_pw(email, pw, h):
    """ Verify password hash """
    salt = h.split('|')[0]
    return h == create_pw_hash(email, pw, salt)

#####   User Login Decorator    #####
def login_required(func):
    """
    A decorator to confirm a user is logged in or redirect as needed.
    """
    def login(self, *args, **kwargs):
        # Redirect to login if user not logged in, else execute func.
        if not self.user:
            self.redirect("/login")
        else:
            func(self, *args, **kwargs)
    return login

########################################################

#################### Master Handler ####################

########################################################

class MasterHandler(webapp2.RequestHandler):
    """ MasterHandler Class """

#Jinja Methods
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

#Cookie Security Methods

    def set_secure_cookie(self, name, val):
        """ Set a secure cookie """
        cookie_val = create_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def check_secure_cookie(self, name):
        """ Check a secure cookie """
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        """ Set cookie upon user login """
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        """ Reset cookie upon user logout """
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        """ Obtain user from cookie when pages are initialized """
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.check_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))

########################################################

################### Database Models ####################

########################################################

class User(db.Model):
    """ Database to store user information """

    email = db.EmailProperty(required=True)
    name = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)

    @classmethod
    def by_email(cls, email):
        return User.all().filter("email =", email).get()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid)

    @classmethod
    def by_name(cls, uid):
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, email, name, pw):
        pw_hash = create_pw_hash(email, pw)
        return User(email = email,
                    name = name,
                    pw_hash = pw_hash)

    @classmethod
    def login(cls, email, pw):
        u = cls.by_email(email)
        if u and validate_pw(email, pw, u.pw_hash):
            return u

class Post(db.Model):
    """ Database to store blog post information """

    title = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now = True)
    user_id = db.IntegerProperty(required=True)
    user = db.StringProperty(required=True)
    likes = db.IntegerProperty(default = 0)

    #Put line breaks in post content
    def render(self):        
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p=self)

class Comment(db.Model):
    """ Database to store post comments """

    comment = db.StringProperty(required=True)
    post = db.StringProperty(required=True)
    commentor = db.StringProperty(required=True)
    user_id = db.IntegerProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now = True)
    
    #Retrieve total number of comments for post
    @classmethod
    def count_by_post_id(cls, post_id):
        c = Comment.all().filter('post =', post_id)
        return c.count()

    #Retrieve al comment for a post
    @classmethod
    def all_by_post_id(cls, post_id):
        c = Comment.all().filter('post =', post_id).order('-created')
        return c

class Like(db.Model):
    """ Database to store post likes """
    post_id = db.IntegerProperty(required = True)
    user_id = db.IntegerProperty(required=True)

########################################################

#################### Page Handlers #####################

########################################################


##############    Front Page    #############

class FrontPage(MasterHandler):
    """ Front Page Handler """
    def get(self):
        # Retrieve all blog posts
        posts = db.GqlQuery("SELECT * FROM Post ORDER BY created DESC limit 10")

        #Validate user
        if self.user:
            self.render('dashboard.html', user = self.user.name, posts=posts)
        else:
            self.render('front.html')

##############    SignUp Page    #############

class SignUpPage(MasterHandler):
    """ Signup Page Handler """
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
    """ Login Page handler """
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
    """ Dashboard page handler """
    @login_required
    def get(self):
        # Retrieve all blog posts
        posts = db.GqlQuery("SELECT * FROM Post ORDER BY created DESC limit 10")
        self.render('dashboard.html', user = self.user.name, posts=posts)

##############    Logout Page    #############

class LogOutPage(MasterHandler):
    """ Logout page handler """
    def get(self):
        self.logout()
        self.redirect("/")

##############    New Post Page    #############

class NewPostPage(MasterHandler):
    """ New Post page handler """
    @login_required
    def get(self):
        self.render('newpost.html')

    @login_required
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
            error = "You need a title and some content to make a new post."
            self.render("newpost.html", title=title, 
                        content=content, error=error)

##############    View Post Page    #############

class ViewPostPage(MasterHandler):
    """ View Post page handler """
    @login_required
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id))
        post = db.get(key)

        if not post:
            return self.error(404)

        #Retrieve comment information
        comments = Comment.all_by_post_id(post_id)
        comments_count = Comment.count_by_post_id(post_id)

        if not post:
            return self.error(404)

        self.render("permalink.html", post=post,
                    comments_count=comments_count,
                    comments=comments)

    @login_required
    def post(self, post_id):
        post = Post.get_by_id(int(post_id))

        #Check is post belongs to user
        if post.user_id == self.user.key().id():
            error = "You cannot like your own post."
            self.render("permalink.html", post=post,
                    comments_count=comments_count,
                    comments=comments, error=error)
        #If not user post, check if user already liked

        #If not liked...

##############    Edit Post Page    #############

class EditPostPage(MasterHandler):
    """ Edit Post page handler """
    @login_required
    def get(self, post_id):

        # Retrieve all blog posts
        posts = db.GqlQuery("SELECT * FROM Post ORDER BY created DESC limit 10")

        key = db.Key.from_path('Post', int(post_id))
        post = db.get(key)
        if post.user_id == self.user.key().id():
            self.render("editpost.html", title=post.title,
                        content=post.content)
        else:
            error = "You do not have access to edit this post."
            self.render("dashboard.html", user = self.user.name,
                    posts=posts, error=error)

    @login_required
    def post(self, post_id):
        title = self.request.get('title')
        content = self.request.get('content')

        key = db.Key.from_path('Post', int(post_id))
        post = db.get(key)

        if post.user_id == self.user.key().id():
            if title and content:
                key = db.Key.from_path('Post', int(post_id))
                post = db.get(key)
                if post:
                    post.title = title
                    post.content = content
                    post.put()
                    self.redirect('/post/%s' % post_id)
                else:
                    error = "This post does not exist."
                    self.render("dashboard.html", user = self.user.name,
                    posts=posts, error=error)
            else:
                error = "You need both a title and some content to update a post."
                self.render("editpost.html", title=title,
                            content=content, error=error)
        else:
                error = "You do not have access to edit this post."
                self.render("dashboard.html", user = self.user.name,
                    posts=posts, error=error)

##############    Delete Post Page    #############

class DeletePostPage(MasterHandler):
    """ Delete Post page handler """
    @login_required
    def get(self, post_id):

        # Retrieve all blog posts
        posts = db.GqlQuery("SELECT * FROM Post ORDER BY created DESC limit 10")

        key = db.Key.from_path('Post', int(post_id))
        post = db.get(key)
        if post is not None:
            if post.user_id == self.user.key().id():
                post.delete()
                error = "Your post has been deleted."
                self.render("deletepost.html", error=error)
            else:
                error = "You do not have access to delete this post."
                self.render("dashboard.html", user = self.user.name,
                    posts=posts, error=error)
        else:
            error = "This post does not exist."
            self.render("dashboard.html", user = self.user.name,
                posts=posts, error=error)

##############    New Comment Page    #############

class NewComment(MasterHandler):
    """ New Comment handler """
    @login_required
    def post (self, post_id):
        key = db.Key.from_path('Post', int(post_id))
        post = db.get(key)
        if not post:
            self.error(404)
            return
        
        comment = self.request.get('comment')

        if comment:
            c = Comment(comment=comment, post=post_id,
                        user_id = self.user.key().id(),
                        commentor = self.user.name)
            c.put()

            #A fix for datastore's Eventual Consistency
            time.sleep(0.1)
            self.redirect('/post/%s' % post_id)

##############    Edit Comment Page    #############

class EditComment(MasterHandler):
    """ Edit Comment handler """
    @login_required
    def get(self, post_id, comment_id):
        post = Post.get_by_id(int(post_id))
        comment = Comment.get_by_id(int(comment_id))

        #Retrieve comment information
        comments = Comment.all_by_post_id(post_id)
        comments_count = Comment.count_by_post_id(post_id)

        if comment and comment.user_id == self.user.key().id():
            self.render("editcomment.html", comment=comment.comment)
        else:
            error = "You cannot edit another users' comments."
            self.render("permalink.html", post=post,
                comments_count=comments_count,
                comments=comments, error=error)

    @login_required
    def post(self, post_id, comment_id):
        post = Post.get_by_id(int(post_id))
        comment = Comment.get_by_id(int(comment_id))
        if comment:
            #Retrieve comment information
            comments = Comment.all_by_post_id(post_id)
            comments_count = Comment.count_by_post_id(post_id)

            if comment.user_id == self.user.key().id():
                comment_content = self.request.get("comment")
                if comment_content:
                    comment.comment = comment_content
                    comment.put()
                    time.sleep(0.1)
                    self.redirect('/post/%s' % post_id)
                else:
                    error = "Please enter a comment."
                    self.render(
                        "editcomment.html",
                    comment=comment.comment)
        else:
            error = "This comment does not exist."
            self.render("permalink.html", post=post,
                    comments_count=comments_count,
                    comments=comments, error=error)

##############    Delete Comment    #############
class DeleteComment(MasterHandler):
    """ Delete Comment handler """
    @login_required
    def get(self, post_id, comment_id):
        post = Post.get_by_id(int(post_id))
        comment = Comment.get_by_id(int(comment_id))

        #Retrieve comment information
        comments = Comment.all_by_post_id(post_id)
        comments_count = Comment.count_by_post_id(post_id)

        if comment:
            if comment.user_id == self.user.key().id():
                comment.delete()
                error = "Your comment has been deleted."
                self.render("deletecomment.html", error=error)
            else:
                error = "You can only delete your own comment."
                self.render("permalink.html", post=post,
                    comments_count=comments_count,
                    comments=comments, error=error)
        else:
            error = "This comment does not exist."
            self.render("permalink.html", post=post,
                    comments_count=comments_count,
                    comments=comments, error=error)

##############    Likes Handler    #############
class LikePost(MasterHandler):
    """ Like Comment handler """
    @login_required
    def get(self, post_id):
        post = Post.get_by_id(int(post_id))
        user = self.user.key().id()
        if post:
            if not post.user_id == user:
                like  = Like.all().filter(
                    'post_id =', int(post_id)).filter('user_id =', user)
                if(like.get()):
                    like[0].delete()
                    post.likes = post.likes - 1
                    post.put()
                    self.redirect('/post/%s' % post_id)
                else:
                    like = Like(post_id = int(post_id), user_id= user)
                    like.put()
                    post.likes = post.likes + 1
                    post.put()
                    self.redirect('/post/%s' % post_id)
            else:
                error = "You cannot like your own post."
                self.render("permalink.html", post = post, error = error)
        else:
            error = "This post does not exist."
            self.render("dashboard.html", user = self.user.name,
                posts=posts, error=error)

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
    ("/post/delete/([0-9]+)", DeletePostPage),
    ("/post/([0-9]+)/like", LikePost),
    ("/post/([0-9]+)/newcomment", NewComment),
    ("/post/([0-9]+)/comment/([0-9]+)/edit", EditComment),
    ("/post/([0-9]+)/comment/([0-9]+)/delete", DeleteComment)
], debug=True)
