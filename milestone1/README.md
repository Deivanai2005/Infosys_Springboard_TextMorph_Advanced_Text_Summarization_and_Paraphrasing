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

Screenshots 
![Sign up](https://github.com/user-attachments/assets/e6167d3e-2971-4e4c-9b2c-5ad505ceeae5)

![Login ](https://github.com/user-attachments/assets/9732435e-762e-46a4-8def-4f5374cd664e)

![Login successful](https://github.com/user-attachments/assets/4318342d-1864-4ee0-9401-1da53fb949a8)

![Dashboard](https://github.com/user-attachments/assets/f3f2c454-cd23-4128-b9da-67f8051db565)

![forgot password](https://github.com/user-attachments/assets/da9b9992-774a-4f56-9734-86be59763cc1)

![Reset   update password](https://github.com/user-attachments/assets/20825760-2241-4bb3-b466-63a2d6e48af5)

