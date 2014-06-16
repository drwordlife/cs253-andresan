#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import webapp2
import jinja2
import os
import re

from google.appengine.ext import db
from webapp2_extras import routes

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
							   autoescape = True)

class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
    	t = jinja_env.get_template(template)
    	return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

class MainHandler(Handler):
    def get(self):
        self.render("mainPage.html")

class HelloUdacityHandler(Handler):
    def get(self):
        self.write("Hello, Udacity!")

class Rot13Handler(Handler):
    def get(self):
        self.render("rot13.html")

    def post(self):
        plain = self.request.get("text")
        ciphered = self.rot13creator(plain)
        self.render("rot13.html", text=ciphered)

    def rot13creator(self, text):
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        ciphertext = ""
        for letter in text:
            if letter.isalpha():
                if letter.isupper():
                    index = ord(letter) - ord('A')
                    index = (index + 13) % 26
                    ciphered_letter = alphabet[index]
                else:
                    index = ord(letter) - ord('a')
                    index = (index + 13) % 26
                    ciphered_letter = alphabet[index].lower()
            else:
            	ciphered_letter = letter

            ciphertext = ciphertext + ciphered_letter
        return ciphertext

class UserSignupHandler(Handler):
    def get(self):
        self.render("userSignup.html")

    def post(self):
        username = self.request.get("username")
        password = self.request.get("password")
        verify = self.request.get("verify")
        email = self.request.get("email")

        username_valid = self.valid_username(username)
        password_valid = self.valid_password(password)
        verify_valid = self.valid_verify(password, verify)
        email_valid = self.valid_email(email)

        if username_valid and password_valid and verify_valid:
            if email and not email_valid:
                self.render("userSignup.html", username=username,
                                               email=email,
                                               email_error="That's an invalid email!")
            else:
                self.redirect("/welcome?username=%s" % username)
        else:
            username_error = ""
            password_error = ""
            verify_error = ""
            email_error = ""
            if not username_valid:
                username_error = "That's an invalid username!"

            if not password_valid:
                password_error = "That's an invalid password!"    
            else:
                if not verify_valid:
                    verify_error = "The passwords don't match!"

            if email and not email_valid:
                email_error = "That's an invalid email!"                    

            self.render("userSignup.html", username=username,
                                           username_error=username_error,
                                           password_error=password_error,
                                           verify_error=verify_error,
                                           email=email,
                                           email_error=email_error)    

    def valid_username(self, username):
        USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
        return USER_RE.match(username)

    def valid_password(self, password):
        PWD_RE = re.compile(r"^.{3,20}$")
        return PWD_RE.match(password)

    def valid_verify(self, password, verify):
        return password == verify

    def valid_email(self, email):
        EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")
        return EMAIL_RE.match(email)

class WelcomeUserSignupHandler(Handler):
    def get(self):
    	username = self.request.get('username')
        self.render("welcomeUserSignup.html", username=username)

class Blog(db.Model):
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    entrydate = db.DateTimeProperty(auto_now_add = True)

class BasicBlogHandler(Handler):
    def render_front(self):
        blog = db.GqlQuery("SELECT * FROM Blog ORDER BY entrydate DESC LIMIT 10")
        self.render("basicBlog.html", blog=blog)

    def get(self):
        self.render_front()

class BasicBlogEntryHandler(Handler):
    def get(self, id):
        blog = Blog.get_by_id(long(id))

        if not blog:
            self.error(404)
            return

        self.render("basicBlogEntry.html", blog=blog)   

class BasicBlogNewPostHandler(Handler):
    def get(self):
        self.render("basicBlogNewPost.html")

    def post(self):
        subject = self.request.get("subject")
        content = self.request.get("content")

        if subject and content:
            blogPost = Blog(subject=subject, content=content)
            blogPost.put()
            newBlogEntryURL = self.uri_for('basicBlogEntry', id=blogPost.key().id())
            self.redirect(newBlogEntryURL)
        else:
            error = "we need both a subject and content to post your entry!"
            self.render("basicBlogNewPost.html", subject=subject, content=content, error=error)

app = webapp2.WSGIApplication([
        webapp2.Route(r'/', handler=MainHandler, name='main'),
        webapp2.Route(r'/helloudacity', handler=HelloUdacityHandler, name='helloUdacity'),
        webapp2.Route(r'/rot13', handler=Rot13Handler, name='rot13'),
        webapp2.Route(r'/usersignup', handler=UserSignupHandler, name='userSignup'),
        webapp2.Route(r'/welcome', handler=WelcomeUserSignupHandler, name='welcomeUserSignup'),
        webapp2.Route(r'/basicblog', handler=BasicBlogHandler, name='basicBlog'),
        webapp2.Route(r'/basicblog/newpost', handler=BasicBlogNewPostHandler, name='basicBlogNewPost'),
        webapp2.Route(r'/basicblog/<id:\d+>', handler=BasicBlogEntryHandler, name='basicBlogEntry')
    ], debug=True)
