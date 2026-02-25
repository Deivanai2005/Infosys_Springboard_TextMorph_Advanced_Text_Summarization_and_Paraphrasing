# Milestone 1 – User Authentication System

## Project Title
TextMorph – Advanced Text Summarization and Paraphrasing

## Internship
Infosys Springboard Internship 6.0 – Batch 13

## Milestone
Milestone 1 – Secure User Authentication System

---

## Description
In this milestone, a secure and functional User Authentication System was designed and implemented as the foundation for the TextMorph project.  
The system is developed using Streamlit for the frontend, JWT for authentication, SQLite for database storage, and Ngrok for exposing the application publicly.

This authentication module will be integrated with Text Summarization and Paraphrasing features in future milestones.

---

## Technologies Used
- Python
- Streamlit
- JWT (JSON Web Token)
- SQLite Database
- Ngrok

---

## Features Implemented

### 1. User Signup
- Username
- Email ID with validation
- Alphanumeric password validation
- Confirm password match
- Security question and answer
- All mandatory field validation

### 2. Secure Login
- Email and password authentication
- Password verification using bcrypt
- JWT token generation on successful login

### 3. Dashboard
- Welcome message displaying username
- Secure logout functionality

### 4. Forgot Password
- Email verification
- Security question verification
- Password reset with validation
- Secure password update in database

### 5. Ngrok Integration
- Streamlit application exposed to the internet using Ngrok
- Public URL generated for demonstration

---

## How to Run the Application

Step 1: Install Dependencies
pip install streamlit pyngrok pyjwt bcrypt
Step 2: Run Streamlit App
streamlit run app.py
Step 3: Expose App Using Ngrok
ngrok http 8501


