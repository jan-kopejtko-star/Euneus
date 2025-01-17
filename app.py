from flask import Flask, render_template

app = Flask(__name__)

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/courses')
def courses():
    # Here you could pass data to your template
    courses_list = [
        {"name": "Basic Penetration Testing", "difficulty": "Beginner"},
        {"name": "Web Security", "difficulty": "Intermediate"},
        {"name": "Malware Analysis", "difficulty": "Advanced"}
    ]
    return render_template('courses.html', courses=courses_list)

@app.route('/labs')
def labs():
    return render_template('labs.html')

@app.route('/tools')
def tools():
    return render_template('tools.html')

@app.route('/profile')
def profile():
    return render_template('profile.html')

if __name__ == '__main__':
    app.run(debug=True)