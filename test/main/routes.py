from flask import render_template, request, Blueprint
from test.models import Post

from flask import Blueprint
main = Blueprint('main',__name__)


@main.route("/")
@main.route("/home")
def hello_world():
    page = request.args.get('page', default=1,type=int)
    posts=Post.query.order_by(Post.date_posted.desc()).paginate(page=page,per_page=2)
    return render_template('home.html',posts=posts)

@main.route("/about")
def about():
    return render_template('about.html', title = 'about page')