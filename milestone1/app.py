//Write app file//
%%writefile app.py
import streamlit as st
import sqlite3
import re
import bcrypt
import jwt
import datetime
import time

st.set_page_config(page_title="TextMorph Auth", page_icon="🔐", layout="centered")

SECRET="SUPER_SECRET_KEY_CHANGE"
DB="users.db"

conn=sqlite3.connect(DB,check_same_thread=False)
cur=conn.cursor()

cur.execute("""
CREATE TABLE IF NOT EXISTS users(
username TEXT,
email TEXT PRIMARY KEY,
password BLOB,
question TEXT,
answer BLOB)
""")
conn.commit()

st.markdown("""
<style>
#MainMenu{visibility:hidden;}
footer{visibility:hidden;}
header{visibility:hidden;}
.stApp{background: linear-gradient(135deg,#0f2027,#203a43,#2c5364);}
.title{text-align:center;font-size:32px;font-weight:bold;margin-bottom:25px;color:#4da3ff;}
</style>
""",unsafe_allow_html=True)

def hash_pw(p):
    return bcrypt.hashpw(p.encode(),bcrypt.gensalt())

def check_pw(p,h):
    return bcrypt.checkpw(p.encode(),h)

def valid_email(e):
    return re.match(r'^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$',e)

def strong_pass(p):
    return re.match(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&]).{8,}$',p)

def token(e):
    payload={"user":e,"exp":datetime.datetime.utcnow()+datetime.timedelta(hours=1)}
    return jwt.encode(payload,SECRET,algorithm="HS256")

if "page" not in st.session_state:
    st.session_state.page="login"
if "user" not in st.session_state:
    st.session_state.user=None

# LOGIN
if st.session_state.page=="login":
    st.markdown("<div class='title'>🔐 TextMorph Login</div>",unsafe_allow_html=True)

    email=st.text_input("Email")
    password=st.text_input("Password",type="password")

    if st.button("Login"):
        cur.execute("SELECT * FROM users WHERE email=?",(email,))
        user=cur.fetchone()
        if user and check_pw(password,user[2]):
            st.session_state.user=user[0]
            token(email)
            st.success("Login Successful 🎉")
            st.session_state.page="dashboard"
            st.rerun()
        else:
            st.error("Invalid email or password")

    col1,col2=st.columns(2)
    if col1.button("Sign Up"):
        st.session_state.page="signup"
        st.rerun()
    if col2.button("Forgot Password"):
        st.session_state.page="forgot"
        st.rerun()

# SIGNUP
elif st.session_state.page=="signup":
    st.markdown("<div class='title'>Create Account</div>",unsafe_allow_html=True)

    u=st.text_input("Username")
    e=st.text_input("Email")
    p=st.text_input("Password",type="password")
    cp=st.text_input("Confirm Password",type="password")

    q=st.selectbox("Security Question",[
        "What is your pet name?",
        "What is your mother’s maiden name?",
        "What is your favorite teacher?"
    ])

    a=st.text_input("Answer")

    if st.button("Create Account"):
        if not all([u,e,p,cp,a]):
            st.error("All fields required")
        elif not valid_email(e):
            st.error("Invalid email format")
        elif not strong_pass(p):
            st.error("Weak password")
        elif p!=cp:
            st.error("Passwords mismatch")
        else:
            try:
                cur.execute("INSERT INTO users VALUES(?,?,?,?,?)",
                (u,e,hash_pw(p),q,hash_pw(a)))
                conn.commit()
                st.success("Account created successfully ✅")
            except:
                st.error("Email already exists")

    if st.button("⬅ Back"):
        st.session_state.page="login"
        st.rerun()

# FORGOT PASSWORD
elif st.session_state.page=="forgot":
    st.markdown("<div class='title'>Reset Password</div>",unsafe_allow_html=True)

    e=st.text_input("Enter Email")

    if st.button("Verify"):
        cur.execute("SELECT question FROM users WHERE email=?",(e,))
        q=cur.fetchone()
        if q:
            st.session_state.reset_email=e
            st.session_state.question=q[0]
        else:
            st.error("Email not found")

    if "question" in st.session_state:
        ans=st.text_input(st.session_state.question)
        newp=st.text_input("New Password",type="password")

        if st.button("Update Password"):
            cur.execute("SELECT answer FROM users WHERE email=?",(st.session_state.reset_email,))
            stored=cur.fetchone()[0]
            if check_pw(ans,stored):
                cur.execute("UPDATE users SET password=? WHERE email=?",
                (hash_pw(newp),st.session_state.reset_email))
                conn.commit()
                st.success("Password updated successfully")
            else:
                st.error("Wrong answer")

    if st.button("⬅ Back"):
        st.session_state.page="login"
        st.rerun()

# DASHBOARD
elif st.session_state.page=="dashboard":
    st.markdown("<div class='title'>🎉 Welcome</div>",unsafe_allow_html=True)
    st.success(f"Hello {st.session_state.user} 👋")

    if st.button("Logout"):
        st.session_state.user=None
        st.session_state.page="login"
        st.rerun()
