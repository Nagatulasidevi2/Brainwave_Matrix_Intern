from flask import Flask, render_template, request
import re

app = Flask(__name__)

common_passwords = [
    "password", "123456", "123456789", "qwerty", "abc123",
    "password1", "111111", "12345678", "iloveyou", "admin"
]

def check_password_strength(password):
    result = {"length": False, "uppercase": False, "lowercase": False,
              "digits": False, "symbols": False, "common": False}

    if len(password) >= 8:
        result["length"] = True
    if re.search(r'[A-Z]', password):
        result["uppercase"] = True
    if re.search(r'[a-z]', password):
        result["lowercase"] = True
    if re.search(r'\d', password):
        result["digits"] = True
    if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        result["symbols"] = True
    if password.lower() in common_passwords:
        result["common"] = True

    if result["common"]:
        strength = "Weak"
    elif all([result["length"], result["uppercase"], result["lowercase"],
              result["digits"], result["symbols"]]):
        strength = "Strong"
    elif result["length"] and (result["uppercase"] or result["lowercase"]) and (result["digits"] or result["symbols"]):
        strength = "Medium"
    else:
        strength = "Weak"

    return strength, result

@app.route('/', methods=['GET', 'POST'])
def index():
    strength = None
    result = {}
    password = ""

    if request.method == 'POST':
        password = request.form['password']
        strength, result = check_password_strength(password)

    return render_template('index.html', strength=strength, result=result, password=password)

if __name__ == '__main__':
    app.run(debug=True)
