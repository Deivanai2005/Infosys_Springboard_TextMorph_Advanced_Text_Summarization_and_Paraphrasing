%%writefile app.py
import streamlit as st
import sqlite3,re,bcrypt,secrets,os,smtplib
import textstat,plotly.graph_objects as go
from email.mime.text import MIMEText
from docx import Document
import PyPDF2

# ---------------- CONFIG ----------------
SECRET="DEV_SECRET"
DB="users.db"

st.set_page_config(page_title="TextMorph",page_icon="📘",layout="centered")

# ---------------- DATABASE ----------------
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

# ---------------- STYLE ----------------
st.markdown("""
<style>
.stApp{background:linear-gradient(135deg,#0f2027,#203a43,#2c5364);}
.title{text-align:center;font-size:32px;font-weight:bold;margin-bottom:25px;color:white;}
h1,h2,h3{color:#ffffff !important;font-weight:700 !important;}
label{color:white !important;font-weight:600;}
input, textarea{
  background:#102b40 !important;
  color:white !important;
  border:1px solid #1f77ff !important;
}
.stButton>button{
  width:100%;
  background:#1f77ff;
  color:white;
  border:none;
  padding:12px;
  border-radius:10px;
  font-weight:bold;
}
</style>
""", unsafe_allow_html=True)

# ---------------- FUNCTIONS ----------------
def hash_pw(p): return bcrypt.hashpw(p.encode(),bcrypt.gensalt())
def check_pw(p,h): return bcrypt.checkpw(p.encode(),h)
def valid_email(e): return re.match(r'^[^@]+@[^@]+\.[^@]+$',e)
def strong_pass(p): return re.match(r'^(?=.*[A-Z])(?=.*[a-z])(?=.*\d).{8,}$',p)

def gauge(val,title):
    return go.Figure(go.Indicator(
        mode="gauge+number",
        value=val,
        number={'suffix':"%"},
        title={'text':title},
        gauge={'axis':{'range':[0,100]}}
    ))

# -------- EMAIL OTP --------
def send_otp(receiver,otp):
    sender=os.getenv("EMAIL_ADDRESS")
    password=os.getenv("EMAIL_PASSWORD")

    msg=MIMEText(f"Your OTP is {otp}")
    msg["Subject"]="Password Reset OTP"
    msg["From"]=sender
    msg["To"]=receiver

    try:
        s=smtplib.SMTP("smtp.gmail.com",587)
        s.starttls()
        s.login(sender,password)
        s.sendmail(sender,receiver,msg.as_string())
        s.quit()
        return True
    except Exception as e:
        print(e)
        return False

# -------- FILE TEXT EXTRACTOR --------
def extract_text(file):
    if file.type=="text/plain":
        return file.read().decode()

    elif "pdf" in file.type:
        reader=PyPDF2.PdfReader(file)
        text=""
        for page in reader.pages:
            text+=page.extract_text()
        return text

    elif "word" in file.type or "document" in file.type:
        doc=Document(file)
        return "\n".join([p.text for p in doc.paragraphs])

    else:
        return ""

# ---------------- SESSION ----------------
if "page" not in st.session_state: st.session_state.page="login"
if "user" not in st.session_state: st.session_state.user=None

# =====================================================
# LOGIN
# =====================================================
if st.session_state.page=="login":

    st.markdown("<div class='title'>🔐 Login</div>",unsafe_allow_html=True)

    email=st.text_input("Email")
    password=st.text_input("Password",type="password")

    if st.button("Login"):
        cur.execute("SELECT * FROM users WHERE email=?",(email,))
        user=cur.fetchone()

        if user and check_pw(password,user[2]):
            st.session_state.user=user[0]
            st.session_state.page="dashboard"
            st.success("Login Successful 🎉")
            st.balloons()
            st.snow()
            st.rerun()
        else:
            st.error("Invalid credentials")

    c1,c2=st.columns(2)
    if c1.button("Sign Up"): st.session_state.page="signup";st.rerun()
    if c2.button("Forgot Password"): st.session_state.page="forgot";st.rerun()

# =====================================================
# SIGNUP
# =====================================================
elif st.session_state.page=="signup":

    st.markdown("<div class='title'>Create Account</div>",unsafe_allow_html=True)

    u=st.text_input("Username")
    e=st.text_input("Email")
    p=st.text_input("Password",type="password")
    cp=st.text_input("Confirm Password",type="password")
    q=st.selectbox("Security Question",
    ["Pet name?","Mother maiden name?","Favorite teacher?"])
    a=st.text_input("Answer")

    if st.button("Create Account"):
        if not all([u,e,p,cp,a]): st.error("Fill all fields")
        elif not valid_email(e): st.error("Invalid email")
        elif not strong_pass(p): st.error("Weak password")
        elif p!=cp: st.error("Passwords mismatch")
        else:
            try:
                cur.execute("INSERT INTO users VALUES(?,?,?,?,?)",
                (u,e,hash_pw(p),q,hash_pw(a)))
                conn.commit()
                st.success("Account created")
            except:
                st.error("Email exists")

    if st.button("Back"): st.session_state.page="login";st.rerun()

# =====================================================
# FORGOT PASSWORD
# =====================================================
elif st.session_state.page=="forgot":

    st.markdown("<div class='title'>Reset Password</div>",unsafe_allow_html=True)

    email=st.text_input("Enter Email")

    if st.button("Send OTP"):
        cur.execute("SELECT email FROM users WHERE email=?",(email,))
        if cur.fetchone():
            otp=str(secrets.randbelow(999999)).zfill(6)
            st.session_state.otp=otp
            st.session_state.reset=email

            if send_otp(email,otp):
                st.success("OTP sent to email")
            else:
                st.error("Failed to send OTP")
        else:
            st.error("Email not found")

    if "otp" in st.session_state:
        code=st.text_input("Enter OTP")
        newp=st.text_input("New Password",type="password")

        if st.button("Reset Password"):
            if code==st.session_state.otp:
                cur.execute("UPDATE users SET password=? WHERE email=?",
                (hash_pw(newp),st.session_state.reset))
                conn.commit()
                st.success("Password reset success")
            else:
                st.error("Wrong OTP")

    if st.button("Back"): st.session_state.page="login";st.rerun()

# =====================================================
# DASHBOARD
# =====================================================
elif st.session_state.page=="dashboard":

    st.markdown("<div class='title'>Dashboard</div>",unsafe_allow_html=True)
    st.success(f"Welcome {st.session_state.user}")

    menu=st.sidebar.selectbox("Menu",["Readability","Logout"])

    if menu=="Readability":
        st.header("📊 Readability Analyzer")

        file=st.file_uploader("📂 Upload file",type=["txt","pdf","docx"])
        txt=""

        if file:
            st.markdown(f"<h4 style='color:#00ffd5;text-align:center;'>📄 {file.name}</h4>",unsafe_allow_html=True)
            txt=extract_text(file)

        txt=st.text_area("Or paste text",txt,height=200)

        word_count=len(txt.split())
        st.caption(f"Word Count: {word_count}")

        analyze_btn = st.button("Analyze", disabled=word_count<50)

        if analyze_btn:
            scores={
            "Flesch":textstat.flesch_reading_ease(txt),
            "Grade":textstat.flesch_kincaid_grade(txt)*5,
            "SMOG":textstat.smog_index(txt)*5,
            "Fog":textstat.gunning_fog(txt)*5,
            "Coleman":textstat.coleman_liau_index(txt)*5,
            "ARI":textstat.automated_readability_index(txt)*5,
            "Linsear":textstat.linsear_write_formula(txt)*5}

            cols=st.columns(3)
            i=0
            for k,v in scores.items():
                val=max(0,min(100,v))
                cols[i%3].plotly_chart(gauge(val,k),use_container_width=True)
                i+=1

    if menu=="Logout":
        st.session_state.user=None
        st.session_state.page="login"
        st.rerun()
